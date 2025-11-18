package main

/*
#include <stdlib.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>

// Console para depuração
void AllocateConsole() {
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
    freopen_s((FILE**)stdin,  "CONIN$",  "r", stdin);
#ifdef UNICODE
    SetConsoleTitle(L"Console de Depuração");
#else
    SetConsoleTitle("Console de Depuração");
#endif
}

// Wrapper para log no console
void ConsoleLog(const char* msg) {
    printf("%s\n", msg);
    fflush(stdout);
}

*/
import "C"

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	domainOverridePort  = 6901
	addressStringMaxLen = 256
	defaultPageSize     = 0x1000

	controlPipeName   = `\\.\pipe\checksum_control`
	reqPipePattern    = `\\.\pipe\checksum_req_%s`
	respPipePattern   = `\\.\pipe\checksum_resp_%s`
	pipeReadDeadline  = 5 * time.Millisecond
	heartbeatInterval = 4 * time.Second
	respQueueTimeout  = 10 * time.Millisecond
)

var (
	WIN32_SEND            uintptr
	WIN32_RECV            uintptr
	CHECKSUM              uintptr
	SEED                  uintptr
	tAddressAddr          uintptr
	domainAddressAddr     uintptr
	domainOverridePtr     unsafe.Pointer
	SHOW_CONSOLE          bool
	SAVE_LOG              bool
	SAVE_SOCKET_LOG       bool
	checksumServerEnabled bool
	pauseOnError          bool
	clientID              string
	reqPipeName           string
	respPipeName          string
	respQueue             = make(chan []byte, 128) // fila interna para respostas
)

var (
	logFile          *os.File
	socketLogFile    *os.File
	originalSend     uintptr
	originalRecv     uintptr
	hookedSendPtr    uintptr
	hookedRecvPtr    uintptr
	counter          int
	found1c0b        bool
	high             uint32
	low              uint32
	sendMutex        sync.Mutex
	kernel32             = windows.NewLazyDLL("kernel32.dll")
	ntdll                = windows.NewLazySystemDLL("ntdll.dll")
	procIsBadReadPtr     = kernel32.NewProc("IsBadReadPtr")
	procPeekNamedPipe    = kernel32.NewProc("PeekNamedPipe")
	procNtProtectVirtualMemory = ntdll.NewProc("NtProtectVirtualMemory")

	consoleInput      *os.File
	checksumRequests  = make(chan *checksumRequest, 32)
	checksumQueued    uint64
	checksumProcessed uint64
	lastSendHookTime  int64
	lastRecvHookTime  int64
)

type checksumRequest struct {
	data     []byte
	counter  int
	low      uint32
	high     uint32
	response chan checksumResponse
}

type checksumResponse struct {
	value byte
}

func parseHexValue(value string) (uintptr, error) {
	parsed, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return 0, err
	}

	return uintptr(parsed), nil
}

func getLastOctet(ip string) int {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 999
	}
	lastOctet, err := strconv.Atoi(parts[3])
	if err != nil {
		return 999
	}
	return lastOctet
}

func getFakeIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "172.65.175.70" // fallback
	}

	found := false
	var allIPs []string

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var filteredAddrs []string
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip != nil && strings.HasPrefix(ip.String(), "172.65.175.") {
				filteredAddrs = append(filteredAddrs, ip.String())
				allIPs = append(allIPs, ip.String())
			}
		}

		if len(filteredAddrs) > 0 {
			found = true
			logInfo(fmt.Sprintf("Interface: %s (Flags: %s)", iface.Name, iface.Flags.String()))
			for _, ip := range filteredAddrs {
				logInfo(fmt.Sprintf("  IP: %s (último octeto: %d)", ip, getLastOctet(ip)))
			}
		}
	}

	if !found {
		return "172.65.175.70"
	}

	selectedIP := "172.65.175.70"
	minOctet := 999

	for _, ip := range allIPs {
		octet := getLastOctet(ip)
		if octet < minOctet {
			minOctet = octet
			selectedIP = ip
		}
	}

	return selectedIP
}

func createDefaultConfigFile(filename string) error {
	content := `WIN32_SEND=14F550C
WIN32_RECV=14F5510
CHECKSUM=518D30
SEED=518F10
T_ADDRESS=14CAE00
DOMAIN_ADDRESS=11514A8
POSEIDON=1
CHECKSUM_SERVER=1
SHOW_CONSOLE=1
SAVE_LOG=1
SAVE_SOCKET_LOG=1
PAUSE_ON_ERROR=1
`

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

func getEnvOverride(key string) (string, bool) {
	envKey := "XKORE1_" + key
	value := os.Getenv(envKey)
	if value != "" {
		return value, true
	}
	return "", false
}

func systemPageSize() uintptr {
	return defaultPageSize
}

func protectMemory(pageBase, size uintptr, newProtect uint32, oldProtect *uint32) (string, error) {
	if err := windows.VirtualProtect(pageBase, size, newProtect, oldProtect); err == nil {
		return "VirtualProtect", nil
	} else {
		lastErr := err
		if procNtProtectVirtualMemory != nil {
			if errNt := ntProtectVirtualMemory(pageBase, size, newProtect, oldProtect); errNt == nil {
				return "NtProtectVirtualMemory", nil
			} else {
				lastErr = errNt
			}
		}
		return "", lastErr
	}
}

func ntProtectVirtualMemory(pageBase, size uintptr, newProtect uint32, oldProtect *uint32) error {
	if procNtProtectVirtualMemory == nil {
		return fmt.Errorf("NtProtectVirtualMemory indisponível")
	}

	baseAddr := pageBase
	regionSize := size
	ret, _, callErr := procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)

	if ret != 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return syscall.Errno(ret)
	}

	return nil
}

func loadConfigFromFile(filename string) (map[string]uintptr, bool, bool, bool, bool, bool) {
	config := make(map[string]uintptr)
	showConsole := true
	saveLog := true
	saveSocketLog := true
	poseidonEnabled := true
	checksumServerEnabled := true

	file, err := os.Open(filename)
	if err != nil {
		logInfo(fmt.Sprintf("Arquivo de configuração %s não encontrado", filename))

		if createErr := createDefaultConfigFile(filename); createErr != nil {
			logInfo(fmt.Sprintf("Erro ao criar arquivo padrão %s: %v", filename, createErr))
			logInfo("Usando valores padrão em memória")
			return config, true, true, true, true, true
		}

		logInfo(fmt.Sprintf("Arquivo %s criado com valores padrão", filename))

		file, err = os.Open(filename)
		if err != nil {
			logInfo(fmt.Sprintf("Erro ao abrir arquivo recém-criado %s: %v", filename, err))
			return config, true, true, true, true, true
		}
	}
	defer file.Close()

	logInfo(fmt.Sprintf("Carregando configuração de %s...", filename))

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			logInfo(fmt.Sprintf("Linha %d ignorada (formato inválido): %s", lineNum, line))
			continue
		}

		key := strings.TrimSpace(parts[0])
		valueStr := strings.TrimSpace(parts[1])

		switch key {
		case "POSEIDON":
			if valueStr == "1" || valueStr == "true" {
				poseidonEnabled = true
			} else {
				poseidonEnabled = false
			}
			logInfo(fmt.Sprintf("  %s=%v", key, poseidonEnabled))
		case "CHECKSUM_SERVER":
			if valueStr == "1" || valueStr == "true" {
				checksumServerEnabled = true
			} else {
				checksumServerEnabled = false
			}
			logInfo(fmt.Sprintf("  %s=%v", key, checksumServerEnabled))
		case "SHOW_CONSOLE":
			if valueStr == "1" || valueStr == "true" {
				showConsole = true
			} else {
				showConsole = false
			}
			logInfo(fmt.Sprintf("  %s=%v", key, showConsole))
		case "SAVE_LOG":
			if valueStr == "1" || valueStr == "true" {
				saveLog = true
			} else {
				saveLog = false
			}
			logInfo(fmt.Sprintf("  %s=%v", key, saveLog))
		case "SAVE_SOCKET_LOG":
			if valueStr == "1" || valueStr == "true" {
				saveSocketLog = true
			} else {
				saveSocketLog = false
			}
			logInfo(fmt.Sprintf("  %s=%v", key, saveSocketLog))
		case "PAUSE_ON_ERROR":
			if valueStr == "1" || strings.ToLower(valueStr) == "true" {
				pauseOnError = true
			} else {
				pauseOnError = false
			}
			logInfo(fmt.Sprintf("  %s=%v", key, pauseOnError))
		default:
			value, err := parseHexValue(valueStr)
			if err != nil {
				logInfo(fmt.Sprintf("Erro na linha %d: %s='%s' - %v", lineNum, key, valueStr, err))
				continue
			}
			config[key] = value
			logInfo(fmt.Sprintf("  %s=0x%x", key, value))
		}
	}

	if err := scanner.Err(); err != nil {
		logInfo(fmt.Sprintf("Erro ao ler arquivo %s: %v", filename, err))
	}

	// Apply environment variable overrides
	logInfo("Verificando variáveis de ambiente para overrides...")

	// Check for hex address overrides
	for key := range config {
		if envValue, found := getEnvOverride(key); found {
			if parsedValue, err := parseHexValue(envValue); err == nil {
				config[key] = parsedValue
				logInfo(fmt.Sprintf("  [ENV] %s=0x%x (sobrescrito por XKORE1_%s)", key, parsedValue, key))
			} else {
				logInfo(fmt.Sprintf("  [ENV] XKORE1_%s inválido: %v", key, err))
			}
		}
	}

	// Check for boolean overrides
	if envValue, found := getEnvOverride("POSEIDON"); found {
		if envValue == "1" || strings.ToLower(envValue) == "true" {
			poseidonEnabled = true
		} else {
			poseidonEnabled = false
		}
		logInfo(fmt.Sprintf("  [ENV] POSEIDON=%v (sobrescrito por XKORE1_POSEIDON)", poseidonEnabled))
	}

	if envValue, found := getEnvOverride("CHECKSUM_SERVER"); found {
		if envValue == "1" || strings.ToLower(envValue) == "true" {
			checksumServerEnabled = true
		} else {
			checksumServerEnabled = false
		}
		logInfo(fmt.Sprintf("  [ENV] CHECKSUM_SERVER=%v (sobrescrito por XKORE1_CHECKSUM_SERVER)", checksumServerEnabled))
	}

	if envValue, found := getEnvOverride("SHOW_CONSOLE"); found {
		if envValue == "1" || strings.ToLower(envValue) == "true" {
			showConsole = true
		} else {
			showConsole = false
		}
		logInfo(fmt.Sprintf("  [ENV] SHOW_CONSOLE=%v (sobrescrito por XKORE1_SHOW_CONSOLE)", showConsole))
	}

	if envValue, found := getEnvOverride("SAVE_LOG"); found {
		if envValue == "1" || strings.ToLower(envValue) == "true" {
			saveLog = true
		} else {
			saveLog = false
		}
		logInfo(fmt.Sprintf("  [ENV] SAVE_LOG=%v (sobrescrito por XKORE1_SAVE_LOG)", saveLog))
	}

	if envValue, found := getEnvOverride("SAVE_SOCKET_LOG"); found {
		if envValue == "1" || strings.ToLower(envValue) == "true" {
			saveSocketLog = true
		} else {
			saveSocketLog = false
		}
		logInfo(fmt.Sprintf("  [ENV] SAVE_SOCKET_LOG=%v (sobrescrito por XKORE1_SAVE_SOCKET_LOG)", saveSocketLog))
	}

	if envValue, found := getEnvOverride("PAUSE_ON_ERROR"); found {
		if envValue == "1" || strings.ToLower(envValue) == "true" {
			pauseOnError = true
		} else {
			pauseOnError = false
		}
		logInfo(fmt.Sprintf("  [ENV] PAUSE_ON_ERROR=%v (sobrescrito por XKORE1_PAUSE_ON_ERROR)", pauseOnError))
	}

	return config, showConsole, saveLog, saveSocketLog, poseidonEnabled, checksumServerEnabled
}

func initConfig() {
	defaults := map[string]uintptr{
		"WIN32_SEND":     0x14F550C,
		"WIN32_RECV":     0x14F5510,
		"CHECKSUM":       0x518D30,
		"SEED":           0x518F10,
		"T_ADDRESS":      0x14CAE00,
		"DOMAIN_ADDRESS": 0x11514A8,
	}

	pauseOnError = true
	var (
		conf             map[string]uintptr
		showConsole      bool
		saveLog          bool
		saveSocketLog    bool
		poseidonEnabled  bool
	)
	conf, showConsole, saveLog, saveSocketLog, poseidonEnabled, checksumServerEnabled = loadConfigFromFile("xkore1_config.txt")

	SHOW_CONSOLE = showConsole
	SAVE_LOG = saveLog
	SAVE_SOCKET_LOG = saveSocketLog
	logInfo(fmt.Sprintf("SHOW_CONSOLE: %v", SHOW_CONSOLE))
	logInfo(fmt.Sprintf("SAVE_LOG: %v", SAVE_LOG))
	logInfo(fmt.Sprintf("SAVE_SOCKET_LOG: %v", SAVE_SOCKET_LOG))
	logInfo(fmt.Sprintf("PAUSE_ON_ERROR: %v", pauseOnError))

	if val, exists := conf["WIN32_SEND"]; exists {
		WIN32_SEND = val
	} else {
		WIN32_SEND = defaults["WIN32_SEND"]
		logInfo(fmt.Sprintf("WIN32_SEND não encontrado no config, usando padrão: 0x%x", WIN32_SEND))
	}

	if val, exists := conf["WIN32_RECV"]; exists {
		WIN32_RECV = val
	} else {
		WIN32_RECV = defaults["WIN32_RECV"]
		logInfo(fmt.Sprintf("WIN32_RECV não encontrado no config, usando padrão: 0x%x", WIN32_RECV))
	}

	if val, exists := conf["CHECKSUM"]; exists {
		CHECKSUM = val
	} else {
		CHECKSUM = defaults["CHECKSUM"]
		logInfo(fmt.Sprintf("CHECKSUM não encontrado no config, usando padrão: 0x%x", CHECKSUM))
	}

	if val, exists := conf["SEED"]; exists {
		SEED = val
	} else {
		SEED = defaults["SEED"]
		logInfo(fmt.Sprintf("SEED não encontrado no config, usando padrão: 0x%x", SEED))
	}

	if val, exists := conf["T_ADDRESS"]; exists {
		tAddressAddr = val
	} else {
		tAddressAddr = defaults["T_ADDRESS"]
		logInfo(fmt.Sprintf("T_ADDRESS não encontrado no config, usando padrão: 0x%x", tAddressAddr))
	}

	if val, exists := conf["DOMAIN_ADDRESS"]; exists {
		domainAddressAddr = val
	} else {
		domainAddressAddr = defaults["DOMAIN_ADDRESS"]
		logInfo(fmt.Sprintf("DOMAIN_ADDRESS não encontrado no config, usando padrão: 0x%x", domainAddressAddr))
	}

	logInfo("Endereços finais inicializados:")
	logInfo(fmt.Sprintf("  WIN32_SEND: 0x%x", WIN32_SEND))
	logInfo(fmt.Sprintf("  WIN32_RECV: 0x%x", WIN32_RECV))
	logInfo(fmt.Sprintf("  CHECKSUM: 0x%x", CHECKSUM))
	logInfo(fmt.Sprintf("  SEED: 0x%x", SEED))
	logInfo(fmt.Sprintf("  T_ADDRESS: 0x%x", tAddressAddr))
	logInfo(fmt.Sprintf("  DOMAIN_ADDRESS: 0x%x", domainAddressAddr))
	logInfo(fmt.Sprintf("  POSEIDON: %v", poseidonEnabled))
	logInfo(fmt.Sprintf("  CHECKSUM_SERVER: %v", checksumServerEnabled))

	if poseidonEnabled {
		applyDomainOverrideOnStartup()
	} else {
		logInfo("[POSEIDON] Disabled - tAddress and domainAddress injection skipped")
	}

	logInfo(fmt.Sprintf("[CHECKSUM SERVER] Habilitado: %v", checksumServerEnabled))
}

func initLogger() {
	var err error

	if SAVE_LOG {
		logFile, err = os.OpenFile("xkore1_logs.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return
		}
		log.SetOutput(logFile)
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	if SAVE_SOCKET_LOG {
		socketLogFile, err = os.OpenFile("xkore1_socket_logs.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return
		}
	}
}

func logInfo(msg string) {
	if SHOW_CONSOLE {
		cMsg := C.CString(fmt.Sprintf("[INFO] %s", msg))
		defer C.free(unsafe.Pointer(cMsg))
		C.ConsoleLog(cMsg)
	}

	if SAVE_LOG && logFile != nil {
		log.Printf("[INFO] %s", msg)
	}
}

func logSocket(direction string, length int, data []byte) {
	if SAVE_SOCKET_LOG && socketLogFile != nil {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		fmt.Fprintf(socketLogFile, "[%s] %s Len: %d Data: %s\n", timestamp, direction, length, bytesToHex(data))
	}
}

func bytesToHex(data []byte) string {
	return fmt.Sprintf("% x", data)
}

func parseUint64Flexible(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("valor vazio")
	}
	return strconv.ParseUint(value, 0, 64)
}

func parseIntFlexible(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("valor vazio")
	}
	parsed, err := strconv.ParseInt(value, 0, 32)
	return int(parsed), err
}

func parseUint32Flexible(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("valor vazio")
	}
	parsed, err := strconv.ParseUint(value, 0, 32)
	return uint32(parsed), err
}

func hexStringToBytes(input string) ([]byte, error) {
	cleaner := strings.NewReplacer(" ", "", "0x", "", "0X", "", "\t", "")
	cleaned := cleaner.Replace(strings.TrimSpace(input))
	if cleaned == "" {
		return nil, fmt.Errorf("sequência hex vazia")
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("número ímpar de dígitos hex: %s", cleaned)
	}
	return hex.DecodeString(cleaned)
}

func splitHexSequences(input string) []string {
	if input == "" {
		return nil
	}
	separators := func(r rune) bool {
		return r == ',' || r == ';' || r == '|'
	}
	raw := strings.FieldsFunc(input, separators)
	var sequences []string
	for _, seq := range raw {
		trimmed := strings.TrimSpace(seq)
		if trimmed != "" {
			sequences = append(sequences, trimmed)
		}
	}
	return sequences
}

func isPointerReadable(addr uintptr, length uintptr) bool {
	if addr == 0 {
		return false
	}
	ret, _, _ := procIsBadReadPtr.Call(addr, length)
	return ret == 0
}

func readPointerValue(addr uintptr) (uintptr, error) {
	if addr == 0 {
		return 0, fmt.Errorf("endereço nulo")
	}

	if !isPointerReadable(addr, unsafe.Sizeof(uintptr(0))) {
		return 0, fmt.Errorf("endereço 0x%x indisponível para leitura", addr)
	}

	return *(*uintptr)(unsafe.Pointer(addr)), nil
}

func writePointerValue(addr, value uintptr) error {
	if addr == 0 {
		return fmt.Errorf("endereço nulo")
	}

	length := unsafe.Sizeof(uintptr(0))
	if !isPointerReadable(addr, length) {
		return fmt.Errorf("endereço 0x%x indisponível para escrita", addr)
	}

	pageBase := addr &^ (systemPageSize() - 1)
	protectSize := systemPageSize()

	protectModes := []uint32{
		windows.PAGE_READWRITE,
		windows.PAGE_WRITECOPY,
		windows.PAGE_EXECUTE_READWRITE,
		windows.PAGE_EXECUTE_WRITECOPY,
	}

	var lastErr error
	for _, mode := range protectModes {
		var oldProtect uint32
		apiUsed, err := protectMemory(pageBase, protectSize, mode, &oldProtect)
		if err != nil {
			lastErr = err
			continue
		}

		*(*uintptr)(unsafe.Pointer(addr)) = value

		var restorePlaceholder uint32
		if _, restoreErr := protectMemory(pageBase, protectSize, oldProtect, &restorePlaceholder); restoreErr != nil {
			logInfo(fmt.Sprintf("Aviso: falha ao restaurar proteção original em 0x%x: %v", addr, restoreErr))
		}

		if apiUsed != "VirtualProtect" {
			logInfo(fmt.Sprintf("[WRITE POINTER] %s aplicado em 0x%x (modo=0x%x)", apiUsed, addr, mode))
		}
		return nil
	}

	return fmt.Errorf("VirtualProtect falhou em 0x%x: %v", addr, lastErr)
}

func readMemoryBytes(addr uintptr, length int) ([]byte, error) {
	if addr == 0 {
		return nil, fmt.Errorf("endereço nulo")
	}
	if length <= 0 {
		return nil, fmt.Errorf("comprimento inválido")
	}

	data := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		current := addr + uintptr(i)
		if !isPointerReadable(current, 1) {
			return nil, fmt.Errorf("endereço 0x%x inacessível para leitura", current)
		}
		byteVal := *(*byte)(unsafe.Pointer(current))
		data = append(data, byteVal)
	}

	return data, nil
}

func readCString(addr uintptr, maxLen int) (string, error) {
	if addr == 0 {
		return "", fmt.Errorf("ponteiro nulo")
	}
	if maxLen <= 0 {
		return "", fmt.Errorf("comprimento máximo inválido")
	}

	bytes := make([]byte, 0, maxLen)
	for i := 0; i < maxLen; i++ {
		current := addr + uintptr(i)
		if !isPointerReadable(current, 1) {
			return "", fmt.Errorf("endereço 0x%x inacessível para leitura", current)
		}
		val := *(*byte)(unsafe.Pointer(current))
		if val == 0 {
			return string(bytes), nil
		}
		bytes = append(bytes, val)
	}

	return string(bytes), fmt.Errorf("string excedeu %d bytes sem terminador nulo", maxLen)
}

func writeCStringToAddress(addr uintptr, value string, maxLen int) error {
	if addr == 0 {
		return fmt.Errorf("endereço nulo")
	}
	if maxLen <= 0 {
		return fmt.Errorf("comprimento máximo inválido")
	}

	value = strings.TrimSpace(value)
	if len(value)+1 > maxLen {
		return fmt.Errorf("valor excede limite de %d bytes", maxLen-1)
	}

	data := append([]byte(value), 0)
	for i, b := range data {
		target := addr + uintptr(i)
		if !isPointerReadable(target, 1) {
			return fmt.Errorf("endereço 0x%x inacessível para escrita", target)
		}
		*(*byte)(unsafe.Pointer(target)) = b
	}

	return nil
}

func readBytesFromPointer(ptr uintptr, length uintptr) []byte {
	if ptr == 0 || length == 0 {
		return nil
	}
	data := make([]byte, int(length))
	for i := uintptr(0); i < length; i++ {
		data[i] = *(*byte)(unsafe.Pointer(ptr + i))
	}
	return data
}

func writeBytesToPointer(ptr uintptr, data []byte) {
	if ptr == 0 || len(data) == 0 {
		return
	}
	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(ptr + uintptr(i))) = data[i]
	}
}

func syncTAddressWithValue(value string) error {
	if tAddressAddr == 0 {
		return fmt.Errorf("T_ADDRESS não configurado")
	}
	return writeCStringToAddress(tAddressAddr, value, addressStringMaxLen)
}

func overrideDomainAddressWithValue(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("valor alvo vazio")
	}

	if domainAddressAddr == 0 {
		return fmt.Errorf("DOMAIN_ADDRESS não configurado")
	}

	if !isPointerReadable(domainAddressAddr, unsafe.Sizeof(uintptr(0))) {
		return fmt.Errorf("endereço base 0x%x inacessível para escrita", domainAddressAddr)
	}

	cStr := C.CString(value)
	if cStr == nil {
		return fmt.Errorf("falha ao alocar string C")
	}

	if domainOverridePtr != nil {
		C.free(domainOverridePtr)
		domainOverridePtr = nil
	}

	ptr := unsafe.Pointer(cStr)
	*(*uintptr)(unsafe.Pointer(domainAddressAddr)) = uintptr(ptr)
	domainOverridePtr = ptr

	if err := syncTAddressWithValue(value); err != nil {
		logInfo(fmt.Sprintf("[VARS] Aviso: falha ao sincronizar tAddress com domainAddress (%v)", err))
	} else {
		logInfo(fmt.Sprintf("[VARS] tAddress sincronizado para %s", value))
	}
	return nil
}

func overrideDomainAddressWithFakeIP() (string, error) {
	newValue := fmt.Sprintf("%s:%d", getFakeIP(), domainOverridePort)
	if err := overrideDomainAddressWithValue(newValue); err != nil {
		return "", err
	}
	return newValue, nil
}

func applyDomainOverrideOnStartup() {
	if domainAddressAddr == 0 {
		logInfo("[VARS] DOMAIN_ADDRESS não configurado; override automático ignorado")
		return
	}

	newValue, err := overrideDomainAddressWithFakeIP()
	if err != nil {
		logInfo(fmt.Sprintf("[VARS] Falha ao ajustar domainAddress automaticamente: %v", err))
		return
	}

	logInfo(fmt.Sprintf("[VARS] domainAddress ajustado automaticamente para %s", newValue))
}

func parsePipePayload(data []byte) ([]byte, int, uint32, uint32, error) {
	if len(data) < 12 {
		return nil, 0, 0, 0, fmt.Errorf("payload curto (%d bytes)", len(data))
	}
	metaStart := len(data) - 12
	payload := data[:metaStart]
	counterVal := int(readUint32(data[metaStart:]))
	seedHigh := readUint32(data[metaStart+4:])
	seedLow := readUint32(data[metaStart+8:])
	return payload, counterVal, seedLow, seedHigh, nil
}

func buildPipeResponse(checksum byte, seedLow, seedHigh uint32, counter int) []byte {
	resp := make([]byte, 0, 13)
	resp = append(resp, checksum)
	resp = append(resp, uint32ToBytes(seedHigh)...)
	resp = append(resp, uint32ToBytes(seedLow)...)
	resp = append(resp, uint32ToBytes(uint32(counter))...)
	return resp
}

func readPipeMessage(f *os.File, _ windows.Handle, deadline time.Duration) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		_ = f.SetReadDeadline(time.Now().Add(deadline))
		n, err := f.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return buf, nil
			}
			if n == 0 {
				return buf, err
			}
		}
		// Se leu algo, tenta imediatamente ler mais até EOF ou deadline
		if n == 0 && len(buf) > 0 {
			return buf, nil
		}
	}
}


func readUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// === Novo fluxo: Pipes separados por cliente + heartbeat ===

func generateClientID() string {
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
}

func startRequestPipeServer() {
	go func() {
		for {
			h, err := windows.CreateNamedPipe(
				windows.StringToUTF16Ptr(reqPipeName),
				windows.PIPE_ACCESS_DUPLEX,
				windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
				windows.PIPE_UNLIMITED_INSTANCES,
				4096, 4096, 0, nil,
			)
			if err != nil {
				logInfo(fmt.Sprintf("[PIPE REQ] Falha ao criar %s: %v", reqPipeName, err))
				time.Sleep(time.Second)
				continue
			}

			if err := windows.ConnectNamedPipe(h, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
				logInfo(fmt.Sprintf("[PIPE REQ] Erro ao aceitar conexão: %v", err))
				_ = windows.CloseHandle(h)
				continue
			}

			go handleRequestPipeConnection(h)
		}
	}()
	logInfo(fmt.Sprintf("[PIPE REQ] Servidor pronto em %s", reqPipeName))
}

func startResponsePipeServer() {
	go func() {
		for {
			h, err := windows.CreateNamedPipe(
				windows.StringToUTF16Ptr(respPipeName),
				windows.PIPE_ACCESS_DUPLEX,
				windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
				windows.PIPE_UNLIMITED_INSTANCES,
				4096, 4096, 0, nil,
			)
			if err != nil {
				logInfo(fmt.Sprintf("[PIPE RESP] Falha ao criar %s: %v", respPipeName, err))
				time.Sleep(time.Second)
				continue
			}

			if err := windows.ConnectNamedPipe(h, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
				logInfo(fmt.Sprintf("[PIPE RESP] Erro ao aceitar conexão: %v", err))
				_ = windows.CloseHandle(h)
				continue
			}

			go handleResponsePipeConnection(h)
		}
	}()
	logInfo(fmt.Sprintf("[PIPE RESP] Servidor pronto em %s", respPipeName))
}

func handleRequestPipeConnection(h windows.Handle) {
	defer windows.CloseHandle(h)
	f := os.NewFile(uintptr(h), "req-pipe")
	if f == nil {
		return
	}
	defer f.Close()

	data, err := readPipeMessage(f, h, pipeReadDeadline)
	if err != nil {
		logInfo(fmt.Sprintf("[PIPE REQ] Falha ao ler: %v", err))
		return
	}

	payload, counterVal, seedLow, seedHigh, err := parsePipePayload(data)
	if err != nil {
		logInfo(fmt.Sprintf("[PIPE REQ] Payload inválido: %v", err))
		return
	}

	logInfo(fmt.Sprintf("[PIPE REQ] len=%d counter=%d seedLow=0x%08x seedHigh=0x%08x", len(payload), counterVal, seedLow, seedHigh))

	checksumByte, newLow, newHigh, err := computeChecksumResponse(payload, counterVal, seedLow, seedHigh)
	if err != nil {
		logInfo(fmt.Sprintf("[PIPE REQ] Erro ao processar: %v", err))
		return
	}

	resp := buildPipeResponse(checksumByte, newLow, newHigh, counterVal)
	respQueue <- resp // bloqueia se fila estiver cheia, garantindo ordem
}

func handleResponsePipeConnection(h windows.Handle) {
	defer windows.CloseHandle(h)
	f := os.NewFile(uintptr(h), "resp-pipe")
	if f == nil {
		return
	}
	defer f.Close()

	var resp []byte
	select {
	case resp = <-respQueue:
	case <-time.After(respQueueTimeout):
		logInfo("[PIPE RESP] Timeout aguardando resposta para enviar")
		return
	}

	if _, err := f.Write(resp); err != nil {
		logInfo(fmt.Sprintf("[PIPE RESP] Falha ao enviar resposta: %v", err))
	} else {
		logInfo(fmt.Sprintf("[PIPE RESP] Resposta enviada (%d bytes)", len(resp)))
	}
}

func startHeartbeat() {
	go func() {
		for {
			sendHeartbeat()
			time.Sleep(heartbeatInterval)
		}
	}()
	sendHeartbeat()
}

func sendHeartbeat() {
	msg := fmt.Sprintf("%s|%s|%s\n", clientID, reqPipeName, respPipeName)
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(controlPipeName),
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		logInfo(fmt.Sprintf("[PIPE CTRL] Não foi possível abrir %s: %v", controlPipeName, err))
		return
	}
	defer windows.CloseHandle(h)

	f := os.NewFile(uintptr(h), "ctrl-pipe")
	if f == nil {
		return
	}
	defer f.Close()

	if _, err := f.Write([]byte(msg)); err != nil {
		logInfo(fmt.Sprintf("[PIPE CTRL] Falha ao enviar heartbeat: %v", err))
	} else {
		logInfo(fmt.Sprintf("[PIPE CTRL] Heartbeat enviado: %s", msg))
	}
}

func computeChecksumResponse(payload []byte, counterVal int, providedLow, providedHigh uint32) (byte, uint32, uint32, error) {
	if len(payload) == 0 {
		return 0, 0, 0, fmt.Errorf("payload vazio")
	}

	sendMutex.Lock()
	defer sendMutex.Unlock()

	isSeedPacket := len(payload) >= 2 && payload[0] == 0x1c && payload[1] == 0x0b

	var checksumByte byte
	switch {
	case counterVal == 0:
		// Sempre gera nova seed quando counter reinicia
		checksumByte = callSeedFunction(payload)
	case !isSeedPacket && (providedLow != 0 || providedHigh != 0):
		checksumByte = callChecksumFunctionWithState(payload, counterVal, providedLow, providedHigh)
	case isSeedPacket:
		if counterVal != 0 {
			checksumByte = callChecksumFunctionWithState(payload, counterVal, providedLow, providedHigh)
		} else {
			checksumByte = callSeedFunction(payload)
		}
	default:
		if high == 0 && low == 0 {
			return 0, 0, 0, fmt.Errorf("seed indisponível; envie um pacote 1C 0B primeiro")
		}
		checksumByte = callChecksumFunctionWithState(payload, counterVal, low, high)
	}

	activeLow := providedLow
	activeHigh := providedHigh
	if activeLow == 0 && activeHigh == 0 {
		activeLow = low
		activeHigh = high
	}

	// Se counter == 0 acabamos de gerar uma seed, portanto active = globais
	if counterVal == 0 {
		activeLow = low
		activeHigh = high
	}

	return checksumByte, activeLow, activeHigh, nil
}

func pauseConsoleForInspection(reason string) {
	if !pauseOnError || !SHOW_CONSOLE {
		return
	}

	logInfo(fmt.Sprintf("[PAUSE] %s", reason))
	logInfo("[PAUSE] Pressione ENTER para finalizar ou feche a janela do console.")

	input, err := os.Open("CONIN$")
	if err != nil {
		logInfo(fmt.Sprintf("[PAUSE] Falha ao abrir CONIN$: %v. Mantendo console aberto por 60 segundos.", err))
		time.Sleep(60 * time.Second)
		return
	}
	defer input.Close()

	reader := bufio.NewReader(input)
	_, _ = reader.ReadString('\n')
}

func handleInitPanic() {
	if r := recover(); r != nil {
		logInfo(fmt.Sprintf("[ERRO] Panic durante inicialização: %v", r))
		stack := debug.Stack()
		if len(stack) > 0 {
			logInfo(fmt.Sprintf("[ERRO] Stacktrace:\n%s", string(stack)))
		}
		pauseConsoleForInspection("Inicialização falhou; inspeção manual habilitada.")
		panic(r)
	}
}

func processChecksumRequests() {
	for {
		select {
		case req := <-checksumRequests:
			if req.response != nil {
				logInfo(fmt.Sprintf("[CHECKSUM CMD] Processando request: Len=%d Counter=%d High=0x%08x Low=0x%08x", len(req.data), req.counter, req.high, req.low))
			}
			atomic.AddUint64(&checksumProcessed, 1)
			value := callChecksumFunctionWithState(req.data, req.counter, req.low, req.high)
			if req.response != nil {
				req.response <- checksumResponse{value: value}
			}
		default:
			return
		}
	}
}

func openConsoleInput() (*os.File, error) {
	if consoleInput != nil {
		return consoleInput, nil
	}

	file, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	handle := windows.Handle(file.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err == nil {
		mode |= windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT
		_ = windows.SetConsoleMode(handle, mode)
	}

	consoleInput = file
	return consoleInput, nil
}

func callSeedFunction(data []byte) byte {
	randByte := int(C.rand()%256) - 128
	logInfo(fmt.Sprintf("[SEED] Random byte: %d", randByte))

	newDataLen := len(data) + 1
	newDataPtr := C.malloc(C.size_t(newDataLen))
	defer C.free(newDataPtr)

	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(uintptr(newDataPtr) + uintptr(i))) = data[i]
	}
	*(*byte)(unsafe.Pointer(uintptr(newDataPtr) + uintptr(len(data)))) = byte(randByte)

	r1, r2, _ := syscall.SyscallN(SEED, uintptr(newDataPtr), uintptr(newDataLen))
	seed := uint64(r1) | (uint64(r2) << 32)
	logInfo(fmt.Sprintf("[SEED] Seed: 0x%x", seed))

	high = uint32(seed >> 32)
	low = uint32(seed & 0xFFFFFFFF)
	logInfo(fmt.Sprintf("[SEED] High: %d, Low: %d", high, low))

	return byte(randByte)
}

func callChecksumFunction(data []byte) byte {
	return callChecksumFunctionWithState(data, counter, low, high)
}

func callChecksumFunctionWithState(data []byte, counterVal int, lowVal, highVal uint32) byte {
	if CHECKSUM == 0 {
		logInfo("CHECKSUM não configurado; impossível calcular checksum manualmente")
		return 0
	}

	if !isPointerReadable(CHECKSUM, unsafe.Sizeof(uintptr(0))) {
		logInfo("Endereço CHECKSUM indisponível nesta instância; provavelmente o mod não está injetado no cliente. Comando abortado.")
		return 0
	}

	var dataPtr uintptr
	if len(data) > 0 {
		buf := C.malloc(C.size_t(len(data)))
		defer C.free(buf)

		for i := 0; i < len(data); i++ {
			*(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(i))) = data[i]
		}
		dataPtr = uintptr(buf)
	}

	defer func() {
		if r := recover(); r != nil {
			logInfo(fmt.Sprintf("[CHECKSUM] Falha ao chamar função nativa: %v", r))
			logInfo("[CHECKSUM] Stack trace:")
			for _, line := range strings.Split(string(debug.Stack()), "\n") {
				logInfo(line)
			}
		}
	}()

	result, _, _ := syscall.SyscallN(CHECKSUM,
		dataPtr,
		uintptr(len(data)),
		uintptr(counterVal),
		uintptr(lowVal),
		uintptr(highVal))

	seedCombined := (uint64(highVal) << 32) | uint64(lowVal)
	logInfo(fmt.Sprintf("[CHECKSUM] Counter: %d, Seed: 0x%016x (High: 0x%x, Low: 0x%x), Resultado: %d (0x%x)",
		counterVal, seedCombined, highVal, lowVal, result, result))
	return byte(result & 0xFF)
}

func hookedRecv(socket, buf, len, flags uintptr) uintptr {
	defer func() {
		if r := recover(); r != nil {
			logInfo(fmt.Sprintf("Erro no hook recv: %v", r))
		}
	}()

	processChecksumRequests()
	atomic.StoreInt64(&lastRecvHookTime, time.Now().UnixNano())

	// Chama a função original
	result, _, _ := syscall.SyscallN(originalRecv, socket, buf, len, flags)

	if result > 0 {
		data := readBytesFromPointer(buf, result)

		// Log simples para socket-logs.txt
		logSocket("RECV", int(result), data)

		// map changed packet
		isc70a := len >= 2 && data[0] == 0xc7 && data[1] == 0x0a
		if isc70a {
			logInfo("[RECV HOOK] PACOTE C7 A0 DETECTADO! ZERANDO COUNTER")
			counter = 0
			// found1c0b = false
		}

		// switch character packetx
		isb300 := len >= 2 && data[0] == 0xb3 && data[1] == 0x00
		if isb300 {
			logInfo("[RECV HOOK] PACOTE B3 00 DETECTADO! ZERANDO COUNTER E found1c0b = false")
			counter = 0
			found1c0b = false
		}

		// c7 0b packet
		isc70b := len >= 2 && data[0] == 0xc7 && data[1] == 0x0b
		if isc70b {
			logInfo("[RECV HOOK] PACOTE C7 0B DETECTADO! DROP PACKET")
			counter = 0
			found1c0b = false
			return 0
		}

		// Log também para o arquivo
		logInfo(fmt.Sprintf("[RECV HOOK] Socket: 0x%x, Len: %d, Data: %s", socket, result, bytesToHex(data)))

	}

	return result
}

func hookedSend(socket, buf, len, flags uintptr) uintptr {
	sendMutex.Lock()
	defer sendMutex.Unlock()

	defer func() {
		if r := recover(); r != nil {
			logInfo(fmt.Sprintf("Erro no hook send: %v", r))
		}
	}()

	processChecksumRequests()
	atomic.StoreInt64(&lastSendHookTime, time.Now().UnixNano())

	currentLen := int(len)
	var data []byte

	if currentLen > 0 && buf != 0 {
		data = readBytesFromPointer(buf, uintptr(currentLen))

		logSocket("SEND", currentLen, data)
		logInfo(fmt.Sprintf("[SEND HOOK] %d, % x", currentLen, data))

		is260c := currentLen >= 2 && data[0] == 0x26 && data[1] == 0x0c
		is1c0b := currentLen >= 2 && data[0] == 0x1c && data[1] == 0x0b

		if is260c {
			counter = 0
			found1c0b = false
			logInfo(fmt.Sprintf("[SEND HOOK] PACOTE 26 0C DETECTADO! Counter zerado: %d", counter))
		}

		if is1c0b {
			found1c0b = true
			logInfo(fmt.Sprintf("[SEND HOOK] PACOTE 1C 0B DETECTADO! Counter: %d", counter))
		}

		if found1c0b && currentLen > 1 {
			discardedByte := data[currentLen-1]
			currentLen--
			data = data[:currentLen]
			logInfo(fmt.Sprintf("[SEND HOOK] DESCARTANDO ULTIMO BYTE! Len original: %d, Nova len: %d, Byte descartado: %d (0x%x)", currentLen+1, currentLen, discardedByte, discardedByte))

			if is1c0b && currentLen >= 2 {
				currentLen = 2
				data = data[:currentLen]
			}

			writeBytesToPointer(buf, data)

			currentData := append([]byte(nil), data[:currentLen]...)

			var resultByte byte
			if counter == 0 {
				logInfo("[SEND HOOK] PRIMEIRO PACOTE 1C 0B - Usando callSeedFunction")
				resultByte = callSeedFunction(currentData)
			} else {
				resultByte = callChecksumFunction(currentData)
			}

			writeBytesToPointer(buf+uintptr(currentLen), []byte{resultByte})
			data = append(data[:currentLen], resultByte)
			currentLen++

			if counter == 0 {
				logInfo(fmt.Sprintf("[SEND HOOK] ADICIONADO SEED BYTE: %d (0x%x) ao final. Nova len: %d", resultByte, resultByte, currentLen))
			} else {
				logInfo(fmt.Sprintf("[SEND HOOK] ADICIONADO CHECKSUM BYTE: %d (0x%x) ao final. Nova len: %d", resultByte, resultByte, currentLen))
			}
		}

		len = uintptr(currentLen)
		logInfo(fmt.Sprintf("[SEND HOOK] Counter: %d, Socket: 0x%x, Len: %d, Flags: 0x%x, Data: % x", counter, socket, len, flags, data))
	} else {
		logInfo(fmt.Sprintf("[SEND HOOK] Counter: %d, Socket: 0x%x, Len: %d, Flags: 0x%x, Data: (null)", counter, socket, len, flags))
	}

	if found1c0b {
		logInfo(fmt.Sprintf("[SEND HOOK] Incrementando counter: %d -> %d", counter, counter+1))
		counter = (counter + 1) & 0xFFF
	}

	result, _, _ := syscall.SyscallN(originalSend, socket, buf, len, flags)
	return result
}

func attemptRecvHook() bool {
	defer func() {
		if r := recover(); r != nil {
			logInfo(fmt.Sprintf("Tentativa de hook recv falhou: %v", r))
		}
	}()

	recvPtrAddress := uintptr(WIN32_RECV)
	logInfo(fmt.Sprintf("Tentando aplicar hook RECV no endereco: 0x%x", recvPtrAddress))

	// Verifica se o endereço é válido para leitura usando IsBadReadPtr
	ret, _, _ := procIsBadReadPtr.Call(recvPtrAddress, unsafe.Sizeof(uintptr(0)))
	if ret != 0 {
		logInfo("ERRO: Endereco RECV invalido para leitura!")
		return false
	}

	// Lê o ponteiro original da função recv
	currentPtr := *(*uintptr)(unsafe.Pointer(recvPtrAddress))
	logInfo(fmt.Sprintf("Ponteiro recv atual: 0x%x", currentPtr))

	if hookedRecvPtr == 0 {
		hookedRecvPtr = syscall.NewCallback(hookedRecv)
		logInfo(fmt.Sprintf("Callback recv criado: 0x%x", hookedRecvPtr))
	}

	if currentPtr == hookedRecvPtr {
		logInfo("Hook RECV já está ativo; nenhuma ação necessária.")
		return true
	}

	if currentPtr == 0 {
		logInfo("ERRO: Ponteiro recv atual eh nulo!")
		return false
	}

	if originalRecv == 0 {
		originalRecv = currentPtr
		logInfo(fmt.Sprintf("Ponteiro recv original salvo: 0x%x", originalRecv))
	} else if originalRecv != currentPtr {
		logInfo(fmt.Sprintf("Ponteiro recv original mudou de 0x%x para 0x%x; preservando valor inicial.", originalRecv, currentPtr))
	}

	if err := writePointerValue(recvPtrAddress, hookedRecvPtr); err != nil {
		logInfo(fmt.Sprintf("ERRO: Falha ao escrever ponteiro RECV: %v", err))
		return false
	}
	logInfo(fmt.Sprintf("Novo ponteiro recv (hook): 0x%x", hookedRecvPtr))

	// Verifica se o hook foi aplicado corretamente
	checkPtr, err := readPointerValue(recvPtrAddress)
	if err != nil {
		logInfo(fmt.Sprintf("ERRO: Falha ao verificar ponteiro RECV: %v", err))
		return false
	}
	if checkPtr == hookedRecvPtr {
		logInfo("Hook RECV aplicado com sucesso!")
		return true
	} else {
		logInfo("ERRO: Hook RECV nao foi aplicado corretamente!")
		return false
	}
}

func attemptHook() bool {
	defer func() {
		if r := recover(); r != nil {
			logInfo(fmt.Sprintf("Tentativa de hook falhou: %v", r))
		}
	}()

	sendPtrAddress := uintptr(WIN32_SEND)
	logInfo(fmt.Sprintf("Tentando aplicar hook SEND no endereco: 0x%x", sendPtrAddress))

	// Verifica se o endereço é válido para leitura usando IsBadReadPtr
	ret, _, _ := procIsBadReadPtr.Call(sendPtrAddress, unsafe.Sizeof(uintptr(0)))
	if ret != 0 {
		logInfo("ERRO: Endereco SEND invalido para leitura!")
		return false
	}

	// Lê o ponteiro original da função send
	currentPtr := *(*uintptr)(unsafe.Pointer(sendPtrAddress))
	logInfo(fmt.Sprintf("Ponteiro send atual: 0x%x", currentPtr))

	if hookedSendPtr == 0 {
		hookedSendPtr = syscall.NewCallback(hookedSend)
		logInfo(fmt.Sprintf("Callback send criado: 0x%x", hookedSendPtr))
	}

	if currentPtr == hookedSendPtr {
		logInfo("Hook SEND já está ativo; nenhuma ação necessária.")
		return true
	}

	if currentPtr == 0 {
		logInfo("ERRO: Ponteiro send atual eh nulo!")
		return false
	}

	if originalSend == 0 {
		originalSend = currentPtr
		logInfo(fmt.Sprintf("Ponteiro send original salvo: 0x%x", originalSend))
	} else if originalSend != currentPtr {
		logInfo(fmt.Sprintf("Ponteiro send original mudou de 0x%x para 0x%x; preservando valor inicial.", originalSend, currentPtr))
	}

	if err := writePointerValue(sendPtrAddress, hookedSendPtr); err != nil {
		logInfo(fmt.Sprintf("ERRO: Falha ao escrever ponteiro SEND: %v", err))
		return false
	}
	logInfo(fmt.Sprintf("Novo ponteiro send (hook): 0x%x", hookedSendPtr))

	// Verifica se o hook foi aplicado corretamente
	checkPtr, err := readPointerValue(sendPtrAddress)
	if err != nil {
		logInfo(fmt.Sprintf("ERRO: Falha ao verificar ponteiro SEND: %v", err))
		return false
	}
	if checkPtr == hookedSendPtr {
		logInfo("Hook SEND aplicado com sucesso!")
		return true
	} else {
		logInfo("ERRO: Hook SEND nao foi aplicado corretamente!")
		return false
	}
}

func setupSendHook() {
	logInfo("Iniciando configuração do hook send...")
	logInfo("Tentando por 60 segundos...")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()

	attempt := 0
	for {
		select {
		case <-timeout.C:
			logInfo("TIMEOUT: Não foi possível configurar o hook send em 60 segundos")
			return
		case <-ticker.C:
			attempt++
			logInfo(fmt.Sprintf("Tentativa %d de configurar hook send...", attempt))

			if attemptHook() {
				logInfo("Hook da função send configurado com sucesso!")
				return
			}

			logInfo("Tentativa falhou, aguardando próxima...")
		}
	}
}

func setupRecvHook() {
	logInfo("Iniciando configuração do hook recv...")
	logInfo("Tentando por 60 segundos...")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()

	attempt := 0
	for {
		select {
		case <-timeout.C:
			logInfo("TIMEOUT: Não foi possível configurar o hook recv em 60 segundos")
			return
		case <-ticker.C:
			attempt++
			logInfo(fmt.Sprintf("Tentativa %d de configurar hook recv...", attempt))

			if attemptRecvHook() {
				logInfo("Hook da função recv configurado com sucesso!")
				return
			}

			logInfo("Tentativa falhou, aguardando próxima...")
		}
	}
}

func init() {
	defer handleInitPanic()

	initConfig()

	initLogger()

	debug.SetPanicOnFault(true)

	if SHOW_CONSOLE {
		C.AllocateConsole()
	}
	startConsoleCommandLoop()

	logInfo("========================================")
	logInfo("     ASI MOD CARREGADO COM SUCESSO!")
	logInfo("========================================")
	logInfo(fmt.Sprintf("Process ID: %d", os.Getpid()))
	logInfo(fmt.Sprintf("Timestamp: %s", time.Now().Format("2006-01-02 15:04:05")))
	logInfo("Mod inicializado com sucesso")

	clientID = generateClientID()
	reqPipeName = fmt.Sprintf(reqPipePattern, clientID)
	respPipeName = fmt.Sprintf(respPipePattern, clientID)
	logInfo(fmt.Sprintf("[PIPE] clientID=%s req=%s resp=%s", clientID, reqPipeName, respPipeName))

	if checksumServerEnabled {
		logInfo("[PIPE] CHECKSUM_SERVER habilitado, iniciando pipes req/resp e heartbeat")
		startRequestPipeServer()
		startResponsePipeServer()
		startHeartbeat()
	} else {
		logInfo("[PIPE] CHECKSUM_SERVER desabilitado; pipes não iniciados")
	}

	go setupSendHook()
	go setupRecvHook()
}

func startConsoleCommandLoop() {
	if !SHOW_CONSOLE {
		return
	}

	input, err := openConsoleInput()
	if err != nil {
		logInfo(fmt.Sprintf("Console interativo indisponível (CONIN$): %v", err))
		return
	}

	go func() {
		logInfo("Console interativo pronto. Digite 'help' para listar comandos disponíveis.")
		scanner := bufio.NewScanner(input)
		buf := make([]byte, 0, 4096)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			handleConsoleCommand(line)
		}
		if err := scanner.Err(); err != nil {
			logInfo(fmt.Sprintf("Erro ao ler comandos do console: %v", err))
		}
	}()
}

func handleConsoleCommand(line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}

	switch strings.ToLower(fields[0]) {
	case "help", "?":
		logInfo("Comandos disponíveis: checksum <seed> <counter> <hex1>[,<hex2>...] | hook <status|retry> | vars [t|domain] | vars domain set")
	case "checksum":
		handleChecksumConsoleCommand(fields)
	case "hook":
		handleHookConsoleCommand(fields[1:])
	case "vars":
		handleVarsConsoleCommand(fields[1:])
	default:
		logInfo(fmt.Sprintf("Comando desconhecido: %s", fields[0]))
	}
}

func handleChecksumConsoleCommand(parts []string) {
	if len(parts) < 4 {
		logInfo("Uso: checksum <seed> <counter> <hex1>[,<hex2>...]")
		return
	}

	if CHECKSUM == 0 || !isPointerReadable(CHECKSUM, unsafe.Sizeof(uintptr(0))) {
		logInfo("Função CHECKSUM indisponível. Verifique se o ASI está injetado e se o endereço está correto antes de usar o comando.")
		return
	}

	seedVal, err := parseUint64Flexible(parts[1])
	if err != nil {
		logInfo(fmt.Sprintf("Seed inválido: %v", err))
		return
	}

	counterVal, err := parseIntFlexible(parts[2])
	if err != nil {
		logInfo(fmt.Sprintf("Counter inválido: %v", err))
		return
	}

	rawPayload := strings.Join(parts[3:], "")
	sequences := splitHexSequences(rawPayload)
	if len(sequences) == 0 {
		logInfo("Nenhuma sequência hex encontrada (use vírgula/; para separar pacotes).")
		return
	}

	highVal := uint32(seedVal >> 32)
	lowVal := uint32(seedVal & 0xFFFFFFFF)
	logInfo(fmt.Sprintf("[CHECKSUM CMD] Seed=0x%016x (High=0x%08x Low=0x%08x) Pacotes=%d CounterInicial=%d",
		seedVal, highVal, lowVal, len(sequences), counterVal))

	currentCounter := counterVal
	for idx, seq := range sequences {
		dataBytes, err := hexStringToBytes(seq)
		if err != nil {
			logInfo(fmt.Sprintf("[CHECKSUM CMD] Pacote %d inválido: %v", idx+1, err))
			continue
		}

		req := &checksumRequest{
			data:     append([]byte(nil), dataBytes...),
			counter:  currentCounter,
			low:      lowVal,
			high:     highVal,
			response: make(chan checksumResponse, 1),
		}

		select {
		case checksumRequests <- req:
			atomic.AddUint64(&checksumQueued, 1)
			logInfo(fmt.Sprintf("[CHECKSUM CMD] #%d aguardando processamento pelo hook. Gere tráfego (mova o personagem, ping, etc.) se demorar.", idx+1))
		case <-time.After(2 * time.Second):
			logInfo("[CHECKSUM CMD] Fila de requisições está cheia. Tente novamente após alguns envios/recebimentos.")
			return
		}

		select {
		case resp := <-req.response:
			logInfo(fmt.Sprintf("[CHECKSUM CMD] #%d Counter=%d Len=%d Checksum=0x%02x",
				idx+1, currentCounter, len(dataBytes), resp.value))
		case <-time.After(5 * time.Second):
			logInfo("[CHECKSUM CMD] Timeout aguardando o hook processar a requisição. Certifique-se de que o jogo esteja enviando/recebendo pacotes e tente novamente.")
			return
		}

		currentCounter = (currentCounter + 1) & 0xFFF
	}
}

func handleHookConsoleCommand(args []string) {
	if len(args) == 0 {
		logInfo("Uso: hook <status|retry>")
		return
	}

	switch strings.ToLower(args[0]) {
	case "status":
		logHookStatus()
	case "retry":
		retryHooks()
	default:
		logInfo(fmt.Sprintf("Subcomando hook desconhecido: %s", args[0]))
	}
}

func handleVarsConsoleCommand(args []string) {
	if len(args) == 0 {
		logTrackedAddressValue("tAddress", tAddressAddr, false)
		logTrackedAddressValue("domainAddress", domainAddressAddr, true)
		return
	}

	for i := 0; i < len(args); i++ {
		token := normalizeVarToken(args[i])
		if token == "" {
			continue
		}

		if isDomainKeyword(token) && i+1 < len(args) && isSetKeyword(args[i+1]) {
			applyDomainOverrideFromCommand()
			i++
			continue
		}

		if isSetKeyword(token) && i+1 < len(args) && isDomainKeyword(args[i+1]) {
			applyDomainOverrideFromCommand()
			i++
			continue
		}

		switch token {
		case "t", "taddress", "t_address":
			logTrackedAddressValue("tAddress", tAddressAddr, false)
		case "d", "domain", "domainaddress", "domain_address":
			logTrackedAddressValue("domainAddress", domainAddressAddr, true)
		case "setdomain", "domainset", "domainoverride", "override-domain":
			applyDomainOverrideFromCommand()
		default:
			logInfo(fmt.Sprintf("[VARS] Identificador desconhecido: %s", args[i]))
		}
	}
}

func normalizeVarToken(input string) string {
	token := strings.TrimSpace(strings.ToLower(input))
	token = strings.Trim(token, "=,;:")
	return token
}

func isDomainKeyword(input string) bool {
	switch normalizeVarToken(input) {
	case "d", "domain", "domainaddr", "domainaddress", "domain_address":
		return true
	default:
		return false
	}
}

func isSetKeyword(input string) bool {
	switch normalizeVarToken(input) {
	case "set", "override", "apply", "update", "fix":
		return true
	default:
		return false
	}
}

func applyDomainOverrideFromCommand() {
	newValue, err := overrideDomainAddressWithFakeIP()
	if err != nil {
		logInfo(fmt.Sprintf("[VARS] Falha ao atualizar domainAddress: %v", err))
		return
	}
	logInfo(fmt.Sprintf("[VARS] domainAddress atualizado para %s", newValue))
	logTrackedAddressValue("domainAddress", domainAddressAddr, true)
	logTrackedAddressValue("tAddress", tAddressAddr, false)
}

func logTrackedAddressValue(name string, baseAddr uintptr, interpretAsPointer bool) {
	logInfo(fmt.Sprintf("[VARS] --- %s ---", name))
	if baseAddr == 0 {
		logInfo(fmt.Sprintf("[VARS] %s: endereço não configurado", name))
		return
	}
	logInfo(fmt.Sprintf("[VARS] %s Endereço monitorado: 0x%x", name, baseAddr))

	if !interpretAsPointer {
		if str, err := readCString(baseAddr, 256); err == nil && str != "" {
			logInfo(fmt.Sprintf("[VARS] %s Conteúdo direto: %q", name, str))
			return
		}

		data, err := readMemoryBytes(baseAddr, 16)
		if err != nil {
			logInfo(fmt.Sprintf("[VARS] %s: não foi possível ler 16 bytes em 0x%x (%v)", name, baseAddr, err))
			return
		}

		logInfo(fmt.Sprintf("[VARS] %s Primeiros 16 bytes @0x%x: % x", name, baseAddr, data))
		return
	}

	value, err := readPointerValue(baseAddr)
	if err != nil {
		logInfo(fmt.Sprintf("[VARS] %s: falha ao ler valor (%v)", name, err))
		return
	}

	logInfo(fmt.Sprintf("[VARS] %s Valor atual: 0x%x (%d)", name, value, value))

	if value == 0 {
		logInfo(fmt.Sprintf("[VARS] %s: valor aponta para 0 (ponteiro nulo)", name))
		return
	}

	if str, err := readCString(value, 256); err == nil && str != "" {
		logInfo(fmt.Sprintf("[VARS] %s String @0x%x: %q", name, value, str))
		return
	}

	data, err := readMemoryBytes(value, 16)
	if err != nil {
		logInfo(fmt.Sprintf("[VARS] %s: não foi possível ler 16 bytes em 0x%x (%v)", name, value, err))
		return
	}

	logInfo(fmt.Sprintf("[VARS] %s Primeiros 16 bytes @0x%x: % x", name, value, data))
}

func logHookStatus() {
	sendPtr, sendErr := readPointerValue(WIN32_SEND)
	recvPtr, recvErr := readPointerValue(WIN32_RECV)

	if sendErr != nil {
		logInfo(fmt.Sprintf("[HOOK STATUS] WIN32_SEND: erro ao ler (%v)", sendErr))
	} else {
		active := hookedSendPtr != 0 && sendPtr == hookedSendPtr
		logInfo(fmt.Sprintf("[HOOK STATUS] WIN32_SEND=0x%x (hook ptr=0x%x) ativo=%v", sendPtr, hookedSendPtr, active))
	}

	if recvErr != nil {
		logInfo(fmt.Sprintf("[HOOK STATUS] WIN32_RECV: erro ao ler (%v)", recvErr))
	} else {
		active := hookedRecvPtr != 0 && recvPtr == hookedRecvPtr
		logInfo(fmt.Sprintf("[HOOK STATUS] WIN32_RECV=0x%x (hook ptr=0x%x) ativo=%v", recvPtr, hookedRecvPtr, active))
	}
}

func retryHooks() {
	logInfo("[HOOK RETRY] Reaplicando hooks SEND/RECV...")
	if attemptHook() {
		logInfo("[HOOK RETRY] SEND hook reaplicado com sucesso.")
	} else {
		logInfo("[HOOK RETRY] Falha ao reaplicar SEND hook.")
	}

	if attemptRecvHook() {
		logInfo("[HOOK RETRY] RECV hook reaplicado com sucesso.")
	} else {
		logInfo("[HOOK RETRY] Falha ao reaplicar RECV hook.")
	}
}

func main() {}
