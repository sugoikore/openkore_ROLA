//go:build windows
// +build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Named pipe bridge: plugin (Perl) TCP -> checksum workers (xkore1) via pipes
// Control pipe (heartbeat): xkore1 envia clientID|reqPipe|respPipe periodicamente
// Para cada requisição TCP, o bridge escolhe um cliente ativo, escreve no reqPipe dele e lê a resposta no respPipe.

const controlPipeName = `\\.\pipe\checksum_control`

var (
	listenHost         string
	listenPort         int
	responseTimeout    time.Duration
	pollDelay          time.Duration
	controlClients     sync.Map // clientID -> *clientInfo
	clientQueues       sync.Map // clientID -> chan workItem
	clientLatency      sync.Map // clientID -> *latencyStats
	modKernel32        = windows.NewLazyDLL("kernel32.dll")
	procPeekNamedPipe  = modKernel32.NewProc("PeekNamedPipe")
)

type clientInfo struct {
	id        string
	reqPipe   string
	respPipe  string
	lastSeen  time.Time
}

type parsedRequest struct {
	payload  []byte
	counter  int
	seedLow  uint32
	seedHigh uint32
}

type heartbeat struct {
	id      string
	reqPipe string
	respPipe string
}

type workItem struct {
	raw      []byte
	response chan []byte
}

type latencyStats struct {
	mu  sync.Mutex
	avg time.Duration
}

func (l *latencyStats) update(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.avg == 0 {
		l.avg = d
		return
	}
	alpha := 0.2
	l.avg = time.Duration((1-alpha)*float64(l.avg) + alpha*float64(d))
}

func (l *latencyStats) deadline() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.avg == 0 {
		return 2 * time.Millisecond
	}
	d := time.Duration(1.2*float64(l.avg)) // small safety factor
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

func startControlPipeListener() {
	go func() {
		for {
			h, err := windows.CreateNamedPipe(
				windows.StringToUTF16Ptr(controlPipeName),
				windows.PIPE_ACCESS_DUPLEX,
				windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
				windows.PIPE_UNLIMITED_INSTANCES,
				4096, 4096, 0, nil,
			)
			if err != nil {
				logInfo(fmt.Sprintf("[CTRL] Falha ao criar control pipe: %v", err))
				time.Sleep(time.Second)
				continue
			}

			if err := windows.ConnectNamedPipe(h, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
				_ = windows.CloseHandle(h)
				continue
			}

			go handleControlConnection(h)
		}
	}()
	logInfo(fmt.Sprintf("[CTRL] Ouvindo heartbeats em %s", controlPipeName))
}

func handleControlConnection(h windows.Handle) {
	defer windows.CloseHandle(h)
	f := os.NewFile(uintptr(h), "ctrl-conn")
	if f == nil {
		return
	}
	defer f.Close()

	data, err := readPipeMessage(f, h, 50*time.Millisecond, 2*time.Second)
	if err != nil {
		logInfo(fmt.Sprintf("[CTRL] Falha ao ler heartbeat: %v", err))
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hb, err := parseHeartbeat(line)
		if err != nil {
			logInfo(fmt.Sprintf("[CTRL] Heartbeat inválido: %s (%v)", line, err))
			continue
		}
		now := time.Now()
		val := &clientInfo{id: hb.id, reqPipe: hb.reqPipe, respPipe: hb.respPipe, lastSeen: now}
		controlClients.Store(hb.id, val)
		ensureClientWorker(hb.id, hb.reqPipe, hb.respPipe)
		logInfo(fmt.Sprintf("[CTRL] Heartbeat de %s req=%s resp=%s", hb.id, hb.reqPipe, hb.respPipe))
	}
}

func parseHeartbeat(line string) (heartbeat, error) {
	parts := strings.Split(line, "|")
	if len(parts) < 3 {
		return heartbeat{}, fmt.Errorf("esperado id|req|resp")
	}
	return heartbeat{
		id:      strings.TrimSpace(parts[0]),
		reqPipe: strings.TrimSpace(parts[1]),
		respPipe: strings.TrimSpace(parts[2]),
	}, nil
}

func gcClients() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		now := time.Now()
		controlClients.Range(func(key, value any) bool {
			cli := value.(*clientInfo)
			if now.Sub(cli.lastSeen) > 5*time.Second {
				logInfo(fmt.Sprintf("[CTRL] Removendo cliente inativo %s", cli.id))
				controlClients.Delete(key)
				if ch, ok := clientQueues.Load(cli.id); ok {
					close(ch.(chan workItem))
					clientQueues.Delete(cli.id)
				}
			}
			return true
		})
	}
}

func pickClient() *clientInfo {
	var selected *clientInfo
	controlClients.Range(func(_, value any) bool {
		cli := value.(*clientInfo)
		if selected == nil || cli.lastSeen.After(selected.lastSeen) {
			selected = cli
		}
		return true
	})
	return selected
}

// ensures a per-client worker that serializes pipe requests
func ensureClientWorker(id, reqPipe, respPipe string) {
	if _, exists := clientQueues.Load(id); exists {
		return
	}
	ch := make(chan workItem, 1)
	clientQueues.Store(id, ch)
	stats := &latencyStats{}
	clientLatency.Store(id, stats)

	go func() {
		for work := range ch {
			start := time.Now()
			if err := writeToPipe(reqPipe, work.raw); err != nil {
				logInfo(fmt.Sprintf("[QUEUE %s] erro escrevendo req: %v", id, err))
				work.response <- nil
				continue
			}
			resp, err := readResponseFromPipe(respPipe, stats.deadline())
			if err != nil {
				logInfo(fmt.Sprintf("[QUEUE %s] erro lendo resp: %v", id, err))
				work.response <- nil
				continue
			}
			stats.update(time.Since(start))
			work.response <- resp
		}
	}()
}

func getClientQueue(cli clientInfo) chan workItem {
	if ch, ok := clientQueues.Load(cli.id); ok {
		return ch.(chan workItem)
	}
	ensureClientWorker(cli.id, cli.reqPipe, cli.respPipe)
	ch, _ := clientQueues.Load(cli.id)
	return ch.(chan workItem)
}

func writeToPipe(name string, data []byte) error {
	h, err := openPipeHandle(name)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	f := os.NewFile(uintptr(h), "pipe-write")
	if f == nil {
		return fmt.Errorf("falha ao criar os.File para pipe")
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("erro escrevendo no pipe: %v", err)
	}
	return nil
}

func readResponseFromPipe(name string, deadline time.Duration) ([]byte, error) {
	h, err := openPipeHandle(name)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	f := os.NewFile(uintptr(h), "pipe-read")
	if f == nil {
		return nil, fmt.Errorf("falha ao criar os.File para pipe")
	}
	defer f.Close()

	resp, err := readPipeMessage(f, h, pollDelay, deadline)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func openPipeHandle(name string) (windows.Handle, error) {
	var h windows.Handle
	var err error
	for i := 0; i < 5; i++ {
		h, err = windows.CreateFile(
			windows.StringToUTF16Ptr(name),
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if err == nil {
			return h, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, fmt.Errorf("falha ao abrir pipe %s: %v", name, err)
}

func main() {
	flag.StringVar(&listenHost, "host", getEnvDefault("CHECKSUM_BRIDGE_HOST", "0.0.0.0"), "Host para escutar TCP do plugin")
	flag.IntVar(&listenPort, "port", envInt("CHECKSUM_BRIDGE_PORT", 2349), "Porta para escutar TCP do plugin")
	flag.DurationVar(&responseTimeout, "response-timeout", 20*time.Millisecond, "Timeout aguardando resposta do pipe")
	flag.DurationVar(&pollDelay, "poll-delay", 500*time.Microsecond, "Intervalo entre polls do pipe de resposta")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", listenHost, listenPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logInfo(fmt.Sprintf("Falha ao escutar em %s: %v", addr, err))
		return
	}
	logInfo(fmt.Sprintf("Bridge escutando TCP em %s; control pipe %s", addr, controlPipeName))

	go startControlPipeListener()
	go gcClients()

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go handleTCPConnection(conn)
	}
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	logInfo(fmt.Sprintf("Conn de %s aberto", conn.RemoteAddr().String()))
	data, err := readTCPMessage(conn, pollDelay, responseTimeout)
	if err != nil {
		logInfo(fmt.Sprintf("Erro lendo do TCP: %v", err))
		return
	}

	req, err := parsePipeRequest(data)
	if err != nil {
		logInfo(fmt.Sprintf("Requisição inválida: %v", err))
		return
	}

	cli := pickClient()
	if cli == nil {
		logInfo("Nenhum cliente ativo disponível")
		return
	}

	logInfo(fmt.Sprintf("TCP req len=%d counter=%d seedLow=0x%08x seedHigh=0x%08x -> client=%s", len(req.payload), req.counter, req.seedLow, req.seedHigh, cli.id))

	resp, err := forwardToPipe(*cli, data)
	if err != nil {
		logInfo(fmt.Sprintf("Erro ao encaminhar para pipe: %v", err))
		return
	}

	if _, err := conn.Write(resp); err != nil {
		logInfo(fmt.Sprintf("Erro ao escrever resposta no TCP: %v", err))
	} else {
		logInfo(fmt.Sprintf("Resposta enviada ao TCP len=%d", len(resp)))
	}
}

func forwardToPipe(cli clientInfo, data []byte) ([]byte, error) {
	workCh := getClientQueue(cli)
	respCh := make(chan []byte, 1)
	select {
	case workCh <- workItem{raw: data, response: respCh}:
	default:
		// fila cheia (deve ser serial), bloqueia
		workCh <- workItem{raw: data, response: respCh}
	}
	resp := <-respCh
	return resp, nil
}

func parsePipeRequest(data []byte) (parsedRequest, error) {
	if len(data) < 12 {
		return parsedRequest{}, fmt.Errorf("dados insuficientes (%d bytes)", len(data))
	}

	metaStart := len(data) - 12
	payload := data[:metaStart]
	counter := int(readUint32(data[metaStart:]))
	seedHigh := readUint32(data[metaStart+4:])
	seedLow := readUint32(data[metaStart+8:])
	return parsedRequest{
		payload:  payload,
		counter:  counter,
		seedLow:  seedLow,
		seedHigh: seedHigh,
	}, nil
}

func readTCPMessage(conn net.Conn, quietWait time.Duration, deadline time.Duration) ([]byte, error) {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 1024)
	end := time.Now().Add(deadline)
	lastRead := time.Now()

	for time.Now().Before(end) {
		_ = conn.SetReadDeadline(time.Now().Add(quietWait))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			lastRead = time.Now()
			continue
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if len(buf) > 0 && time.Since(lastRead) >= quietWait {
					return buf, nil
				}
				continue
			}
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return buf, nil
			}
			return buf, err
		}
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("timeout lendo TCP")
	}
	return buf, nil
}

func logInfo(msg string) {
	fmt.Printf("[BRIDGE] %s\n", msg)
}

func readUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// readPipeMessage reads from the named pipe until there is no more pending data
// for a quiet period (quietWait) or until deadline is reached.
func readPipeMessage(f *os.File, h windows.Handle, quietWait time.Duration, deadline time.Duration) ([]byte, error) {
	var buf []byte
	quietSince := time.Now()
	end := time.Now().Add(deadline)

	for time.Now().Before(end) {
		// how many bytes are available?
		avail, err := peekNamedPipeAvail(h)
		if err != nil {
			time.Sleep(quietWait)
			continue
		}

		if avail > 0 {
			tmp := make([]byte, avail)
			n, err := f.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return buf, err
			}
			quietSince = time.Now()
		} else {
			if len(buf) > 0 && time.Since(quietSince) >= quietWait {
				return buf, nil
			}
			time.Sleep(quietWait)
		}
	}

	if len(buf) == 0 {
		return nil, fmt.Errorf("timeout aguardando dados no pipe")
	}
	return buf, nil
}

func peekNamedPipeAvail(handle windows.Handle) (uint32, error) {
	var avail uint32
	r1, _, e1 := procPeekNamedPipe.Call(
		uintptr(handle),
		0, 0,
		0,
		uintptr(unsafe.Pointer(&avail)),
		0,
	)
	if r1 == 0 {
		if e1 != nil {
			return 0, e1
		}
		return 0, fmt.Errorf("PeekNamedPipe failed")
	}
	return avail, nil
}
