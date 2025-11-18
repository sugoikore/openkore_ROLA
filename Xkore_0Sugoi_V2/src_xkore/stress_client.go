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
	"sync"
	"sync/atomic"
	"time"
)

var (
	host       = flag.String("host", "127.0.0.1", "Checksum server host")
	port       = flag.Int("port", 2349, "Checksum server port")
	reqsPerSec = flag.Int("rate", 100, "Target requests per second")
	workers    = flag.Int("workers", 10, "Number of concurrent workers")
	minPayload = flag.Int("min-bytes", 5, "Minimum payload size (bytes)")
	maxPayload = flag.Int("max-bytes", 80, "Maximum payload size (bytes)")
	timeout    = flag.Duration("timeout", time.Second, "Socket timeout")
	replayMode = flag.Bool("replay", false, "Enable CSV replay mode")
	csvFile    = flag.String("csv", "checksum_data.csv", "CSV file to replay")
	username   = flag.String("username", "testuser", "Username prefix for requests (não é enviado)")
	replayRandom = flag.Bool("replay-random", false, "Replay CSV in random order (default: sequential)")

	counterMask = 0xFFF
)

type csvRecord struct {
	counter   int
	seedHigh  uint32
	seedLow   uint32
	packetHex string
	checksum  byte
}

type stats struct {
	totalSent      uint64
	totalSucceeded uint64
	totalFailed    uint64
	totalMismatch  uint64
}

func (s *stats) addSent()      { atomic.AddUint64(&s.totalSent, 1) }
func (s *stats) addSucceeded() { atomic.AddUint64(&s.totalSucceeded, 1) }
func (s *stats) addFailed()    { atomic.AddUint64(&s.totalFailed, 1) }
func (s *stats) addMismatch()  { atomic.AddUint64(&s.totalMismatch, 1) }

func (s *stats) get() (sent, succeeded, failed, mismatch uint64) {
	return atomic.LoadUint64(&s.totalSent),
		atomic.LoadUint64(&s.totalSucceeded),
		atomic.LoadUint64(&s.totalFailed),
		atomic.LoadUint64(&s.totalMismatch)
}

type rateLimiter struct {
	interval time.Duration
	ticker   *time.Ticker
	tokens   chan struct{}
}

func newRateLimiter(rps int) *rateLimiter {
	rl := &rateLimiter{
		interval: time.Second / time.Duration(rps),
		tokens:   make(chan struct{}, rps),
	}

	// Fill initial tokens
	for i := 0; i < rps; i++ {
		rl.tokens <- struct{}{}
	}

	// Refill tokens
	rl.ticker = time.NewTicker(rl.interval)
	go func() {
		for range rl.ticker.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
	}()

	return rl
}

func (rl *rateLimiter) wait() {
	<-rl.tokens
}

func (rl *rateLimiter) stop() {
	rl.ticker.Stop()
}

func main() {
	flag.Parse()

	if *reqsPerSec <= 0 {
		log.Fatalf("invalid rate: %d (must be > 0)", *reqsPerSec)
	}

	if *workers <= 0 {
		log.Fatalf("invalid workers: %d (must be > 0)", *workers)
	}

	if *minPayload <= 0 || *maxPayload < *minPayload {
		log.Fatalf("invalid payload size range: min=%d max=%d", *minPayload, *maxPayload)
	}

	serverAddr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("[STRESS] Target server: %s", serverAddr)
	log.Printf("[STRESS] Rate: %d req/s, Workers: %d", *reqsPerSec, *workers)
	log.Printf("[STRESS] Username (ignorado no protocolo): %s", *username)

	if *replayMode {
		log.Printf("[STRESS] Running in REPLAY mode using CSV file: %s (random=%v)", *csvFile, *replayRandom)
		runReplayMode(serverAddr, *username, *replayRandom)
	} else {
		log.Printf("[STRESS] Running in RANDOM mode")
		runRandomMode(serverAddr, *username)
	}
}

func runReplayMode(serverAddr string, username string, randomOrder bool) {
	records, err := loadCSVRecords(*csvFile)
	if err != nil {
		log.Fatalf("[REPLAY] Failed to load CSV file: %v", err)
	}

	if len(records) == 0 {
		log.Fatalf("[REPLAY] No records found in CSV file")
	}

	log.Printf("[REPLAY] Loaded %d records from CSV", len(records))

	st := &stats{}
	limiter := newRateLimiter(*reqsPerSec)
	defer limiter.stop()

	// Start statistics reporter
	go reportStats(st, true)

	// Start workers
	var wg sync.WaitGroup
	var idx uint64
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for {
				limiter.wait()

				var record csvRecord
				if randomOrder {
					record = records[rng.Intn(len(records))]
				} else {
					pos := atomic.AddUint64(&idx, 1) - 1
					record = records[pos%uint64(len(records))]
				}

				payload, err := parseHexString(record.packetHex)
				if err != nil {
					log.Printf("[REPLAY][W%d][ERROR] Failed to parse hex: %v", workerID, err)
					continue
				}

					respChecksum, respSeed, err := sendRequest(serverAddr, username, payload, record.counter, record.seedHigh, record.seedLow)
				st.addSent()

				if err != nil {
					st.addFailed()
					continue
				}

				st.addSucceeded()

				if respChecksum != record.checksum {
					st.addMismatch()
					log.Printf("[REPLAY][W%d][MISMATCH] counter=%d expected=0x%02x got=0x%02x seed=0x%08x%08x",
						workerID, record.counter, record.checksum, respChecksum, respSeed.high, respSeed.low)
				}
			}
		}(i)
	}

	wg.Wait()
}

func runRandomMode(serverAddr string, username string) {
	st := &stats{}
	limiter := newRateLimiter(*reqsPerSec)
	defer limiter.stop()

	// Start statistics reporter
	go reportStats(st, false)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			counter := workerID * 100 // Offset counter per worker to avoid collisions
			var currentSeedHi, currentSeedLo uint32

			for {
				limiter.wait()

				payload := randomPayload(rng, *minPayload, *maxPayload)
				_, respSeed, err := sendRequest(serverAddr, username, payload, counter, currentSeedHi, currentSeedLo)
				st.addSent()

				if err != nil {
					st.addFailed()
					continue
				}

				st.addSucceeded()
				currentSeedHi = respSeed.high
				currentSeedLo = respSeed.low

				counter = (counter + 1) & counterMask
				if counter == 0 {
					currentSeedHi = 0
					currentSeedLo = 0
				}
			}
		}(i)
	}

	wg.Wait()
}

func reportStats(st *stats, isReplay bool) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastSent := uint64(0)
	lastTime := time.Now()

	for range ticker.C {
		sent, succeeded, failed, mismatch := st.get()

		now := time.Now()
		elapsed := now.Sub(lastTime).Seconds()
		currentRate := float64(sent-lastSent) / elapsed

		if isReplay {
			log.Printf("[STATS] Rate: %.1f req/s | Total: sent=%d success=%d failed=%d mismatch=%d",
				currentRate, sent, succeeded, failed, mismatch)
		} else {
			log.Printf("[STATS] Rate: %.1f req/s | Total: sent=%d success=%d failed=%d",
				currentRate, sent, succeeded, failed)
		}

		lastSent = sent
		lastTime = now
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
			continue
		}

		counter, err := strconv.Atoi(row[1])
		if err != nil {
			continue
		}

		seedHigh, err := strconv.ParseUint(row[2], 10, 32)
		if err != nil {
			continue
		}

		seedLow, err := strconv.ParseUint(row[3], 10, 32)
		if err != nil {
			continue
		}

		checksumVal, err := strconv.ParseUint(row[6], 10, 8)
		if err != nil {
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
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	return hex.DecodeString(hexStr)
}

type seedPair struct {
	high uint32
	low  uint32
}

func sendRequest(addr string, username string, payload []byte, counter int, seedHigh, seedLow uint32) (byte, seedPair, error) {
	conn, err := net.DialTimeout("tcp", addr, *timeout)
	if err != nil {
		return 0, seedPair{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(*timeout))

	packet := make([]byte, 0, len(payload)+12)
	packet = append(packet, payload...)

	meta := make([]byte, 12)
	binary.BigEndian.PutUint32(meta[0:4], uint32(counter))
	binary.BigEndian.PutUint32(meta[4:8], seedHigh)
	binary.BigEndian.PutUint32(meta[8:12], seedLow)
	packet = append(packet, meta...)

	if _, err := conn.Write(packet); err != nil {
		return 0, seedPair{}, err
	}

	// Resposta: 1B checksum + seedHigh + seedLow + counter
	rest := make([]byte, 13)
	if _, err := ioReadFull(conn, rest); err != nil {
		return 0, seedPair{}, err
	}

	checksum := rest[0]
	return checksum, seedPair{
		high: binary.BigEndian.Uint32(rest[1:5]),
		low:  binary.BigEndian.Uint32(rest[5:9]),
	}, nil
}

func randomPayload(rng *rand.Rand, min, max int) []byte {
	size := min
	if max > min {
		size = min + rng.Intn(max-min+1)
	}
	buf := make([]byte, size)
	rng.Read(buf)
	return buf
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
