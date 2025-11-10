package main

import (
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	host        = flag.String("host", "127.0.0.1", "Checksum server host")
	port        = flag.Int("port", 2349, "Checksum server port")
	minReqPerS  = flag.Int("min", 1, "Minimum requests per second")
	maxReqPerS  = flag.Int("max", 15, "Maximum requests per second")
	minPayload  = flag.Int("min-bytes", 5, "Minimum payload size (bytes)")
	maxPayload  = flag.Int("max-bytes", 80, "Maximum payload size (bytes)")
	timeout     = flag.Duration("timeout", time.Second, "Socket timeout")
	replayMode  = flag.Bool("replay", false, "Enable CSV replay mode")
	csvFile     = flag.String("csv", "checksum_data.csv", "CSV file to replay")
	seed        = rand.New(rand.NewSource(time.Now().UnixNano()))
	counterMask = 0xFFF
)

type csvRecord struct {
	counter   int
	seedHigh  uint32
	seedLow   uint32
	packetHex string
	checksum  byte
}

func main() {
	flag.Parse()

	if *minReqPerS <= 0 || *maxReqPerS < *minReqPerS {
		log.Fatalf("invalid rate range: min=%d max=%d", *minReqPerS, *maxReqPerS)
	}

	if *minPayload <= 0 || *maxPayload < *minPayload {
		log.Fatalf("invalid payload size range: min=%d max=%d", *minPayload, *maxPayload)
	}

	serverAddr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("[STRESS] Target server: %s", serverAddr)

	if *replayMode {
		log.Printf("[STRESS] Running in REPLAY mode using CSV file: %s", *csvFile)
		runReplayMode(serverAddr)
	} else {
		log.Printf("[STRESS] Running in RANDOM mode")
		runRandomMode(serverAddr)
	}
}

func runReplayMode(serverAddr string) {
	// Load CSV records
	records, err := loadCSVRecords(*csvFile)
	if err != nil {
		log.Fatalf("[REPLAY] Failed to load CSV file: %v", err)
	}

	if len(records) == 0 {
		log.Fatalf("[REPLAY] No records found in CSV file")
	}

	log.Printf("[REPLAY] Loaded %d records from CSV", len(records))

	var (
		totalSent      = 0
		totalSucceeded = 0
		totalFailed    = 0
		totalMismatch  = 0
	)

	minInterval := time.Second / time.Duration(*maxReqPerS)
	maxInterval := time.Second / time.Duration(*minReqPerS)

	// Loop infinitely, randomly selecting records
	for {
		interval := randomDuration(minInterval, maxInterval)
		time.Sleep(interval)

		// Randomly select a record
		record := records[seed.Intn(len(records))]

		// Parse hex packet data
		payload, err := parseHexString(record.packetHex)
		if err != nil {
			log.Printf("[REPLAY][ERROR] Failed to parse hex data: %v", err)
			continue
		}

		// Send request and get response
		respChecksum, respSeed, err := sendRequest(serverAddr, payload, record.counter, record.seedHigh, record.seedLow)
		totalSent++

		if err != nil {
			totalFailed++
			log.Printf("[REPLAY][ERROR] counter=%d len=%d err=%v", record.counter, len(payload), err)
			continue
		}

		totalSucceeded++

		// Verify checksum matches expected value
		if respChecksum != record.checksum {
			totalMismatch++
			log.Printf("[REPLAY][MISMATCH] counter=%d len=%d expected=0x%02x got=0x%02x seed=0x%08x%08x",
				record.counter, len(payload), record.checksum, respChecksum, respSeed.high, respSeed.low)
		} else {
			log.Printf("[REPLAY][OK] counter=%d len=%d checksum=0x%02x seed=0x%08x%08x totals(sent=%d success=%d failed=%d mismatch=%d)",
				record.counter, len(payload), respChecksum, respSeed.high, respSeed.low, totalSent, totalSucceeded, totalFailed, totalMismatch)
		}
	}
}

func runRandomMode(serverAddr string) {
	var (
		counter        = 0
		currentSeedHi  uint32
		currentSeedLo  uint32
		totalSent      = 0
		totalSucceeded = 0
		totalFailed    = 0
	)

	minInterval := time.Second / time.Duration(*maxReqPerS)
	maxInterval := time.Second / time.Duration(*minReqPerS)

	for {
		interval := randomDuration(minInterval, maxInterval)
		time.Sleep(interval)

		payload := randomPayload(*minPayload, *maxPayload)
		_, respSeed, err := sendRequest(serverAddr, payload, counter, currentSeedHi, currentSeedLo)
		totalSent++

		if err != nil {
			totalFailed++
			log.Printf("[STRESS][ERROR] counter=%d len=%d err=%v", counter, len(payload), err)
			continue
		}

		totalSucceeded++
		currentSeedHi = respSeed.high
		currentSeedLo = respSeed.low

		log.Printf("[STRESS][OK] counter=%d len=%d seed=0x%08x%08x totals(sent=%d success=%d failed=%d)",
			counter, len(payload), currentSeedHi, currentSeedLo, totalSent, totalSucceeded, totalFailed)

		counter = (counter + 1) & counterMask
		if counter == 0 {
			// let server generate a fresh seed on next request
			currentSeedHi = 0
			currentSeedLo = 0
		}
	}
}

func loadCSVRecords(filename string) ([]csvRecord, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header
	_, err = reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	var records []csvRecord
	lineNum := 1

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV line %d: %w", lineNum, err)
		}
		lineNum++

		if len(row) < 7 {
			log.Printf("[REPLAY] Skipping line %d: insufficient columns", lineNum)
			continue
		}

		// Parse: timestamp,counter,seed_high,seed_low,packet_hex,packet_length,checksum
		counter, err := strconv.Atoi(row[1])
		if err != nil {
			log.Printf("[REPLAY] Skipping line %d: invalid counter: %v", lineNum, err)
			continue
		}

		seedHigh, err := strconv.ParseUint(row[2], 10, 32)
		if err != nil {
			log.Printf("[REPLAY] Skipping line %d: invalid seed_high: %v", lineNum, err)
			continue
		}

		seedLow, err := strconv.ParseUint(row[3], 10, 32)
		if err != nil {
			log.Printf("[REPLAY] Skipping line %d: invalid seed_low: %v", lineNum, err)
			continue
		}

		checksumVal, err := strconv.ParseUint(row[6], 10, 8)
		if err != nil {
			log.Printf("[REPLAY] Skipping line %d: invalid checksum: %v", lineNum, err)
			continue
		}

		records = append(records, csvRecord{
			counter:   counter,
			seedHigh:  uint32(seedHigh),
			seedLow:   uint32(seedLow),
			packetHex: row[4],
			checksum:  byte(checksumVal),
		})
	}

	return records, nil
}

func parseHexString(hexStr string) ([]byte, error) {
	// Remove spaces
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	return hex.DecodeString(hexStr)
}

type seedPair struct {
	high uint32
	low  uint32
}

func sendRequest(addr string, payload []byte, counter int, seedHigh, seedLow uint32) (byte, seedPair, error) {
	conn, err := net.DialTimeout("tcp", addr, *timeout)
	if err != nil {
		return 0, seedPair{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(*timeout))

	packet := make([]byte, len(payload)+12)
	copy(packet, payload)
	meta := packet[len(payload):]
	binary.BigEndian.PutUint32(meta[0:4], uint32(counter))
	binary.BigEndian.PutUint32(meta[4:8], seedHigh)
	binary.BigEndian.PutUint32(meta[8:12], seedLow)

	if _, err := conn.Write(packet); err != nil {
		return 0, seedPair{}, err
	}

	resp := make([]byte, 17)
	if _, err := ioReadFull(conn, resp); err != nil {
		return 0, seedPair{}, err
	}

	checksum := resp[0]
	return checksum, seedPair{
		high: binary.BigEndian.Uint32(resp[1:5]),
		low:  binary.BigEndian.Uint32(resp[5:9]),
	}, nil
}

func randomPayload(min, max int) []byte {
	size := min
	if max > min {
		size = min + seed.Intn(max-min+1)
	}
	buf := make([]byte, size)
	if _, err := seed.Read(buf); err != nil {
		for i := range buf {
			buf[i] = byte(seed.Intn(256))
		}
	}
	return buf
}

func randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	diff := max - min
	return min + time.Duration(seed.Int63n(int64(diff)+1))
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		if n > 0 {
			read += n
		}
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
