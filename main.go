package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type ProxyChecker struct {
	ProxyURLs        map[string][]string
	Timeout          time.Duration
	MaxRetries       int
	RetryDelay       time.Duration
	MaxWorkers       int
	LogCallback      func(string)
	ProgressCallback func(int)
	CancelContext    context.Context
	CancelFunc       context.CancelFunc
}

func NewProxyChecker(proxyURLs map[string][]string, timeout time.Duration, maxRetries int, retryDelay time.Duration, maxWorkers int, logCallback func(string), progressCallback func(int)) *ProxyChecker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProxyChecker{
		ProxyURLs:        proxyURLs,
		Timeout:          timeout,
		MaxRetries:       maxRetries,
		RetryDelay:       retryDelay,
		MaxWorkers:       maxWorkers,
		LogCallback:      logCallback,
		ProgressCallback: progressCallback,
		CancelContext:    ctx,
		CancelFunc:       cancel,
	}
}

func (pc *ProxyChecker) Log(level, message string) {
	fullMessage := fmt.Sprintf("%s: %s", level, message)
	if pc.LogCallback != nil {
		pc.LogCallback(fullMessage)
	} else {
		log.Println(fullMessage)
	}
}

func (pc *ProxyChecker) Cancel() {
	pc.CancelFunc()
	pc.Log("INFO", "Cancellation requested")
}

// Verifies if a SOCKS4 proxy is working
func (pc *ProxyChecker) CheckSOCKS4(proxy string) bool {
	ctx, cancel := context.WithTimeout(pc.CancelContext, pc.Timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: pc.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline := time.Now().Add(pc.Timeout)
	conn.SetDeadline(deadline)

	// SOCKS4 handshake
	_, err = conn.Write([]byte{0x04, 0x01, 0x00, 0x50, 0x01, 0x01, 0x01, 0x01, 0x00})
	if err != nil {
		return false
	}

	response := make([]byte, 2)
	_, err = conn.Read(response)
	if err != nil {
		return false
	}

	// Check if the connection was successful
	return response[1] == 0x5A
}

// Verifies if a SOCKS5 proxy is working
func (pc *ProxyChecker) CheckSOCKS5(proxy string) bool {
	ctx, cancel := context.WithTimeout(pc.CancelContext, pc.Timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: pc.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline := time.Now().Add(pc.Timeout)
	conn.SetDeadline(deadline)

	// SOCKS5 handshake
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return false
	}

	response := make([]byte, 2)
	_, err = conn.Read(response)
	if err != nil {
		return false
	}

	// Check if the authentication method is accepted
	if response[1] != 0x00 {
		return false
	}

	// Send connection request to 1.1.1.1:80
	_, err = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x50})
	if err != nil {
		return false
	}

	response = make([]byte, 10)
	_, err = conn.Read(response)
	if err != nil {
		return false
	}

	// Check if the connection was successful
	return response[1] == 0x00
}

// Verifies if an HTTP proxy is working using the CONNECT method
func (pc *ProxyChecker) CheckHTTP(proxy string) bool {
	ctx, cancel := context.WithTimeout(pc.CancelContext, pc.Timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: pc.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline := time.Now().Add(pc.Timeout)
	conn.SetDeadline(deadline)

	// Send CONNECT request to the proxy
	connectRequest := "CONNECT 1.1.1.1:80 HTTP/1.1\r\nHost: 1.1.1.1:80\r\n\r\n"
	_, err = conn.Write([]byte(connectRequest))
	if err != nil {
		return false
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check if the response indicates a successful connection
	return strings.HasPrefix(response, "HTTP/1.1 200")
}

func (pc *ProxyChecker) CheckProxy(proxyType, proxy string) bool {
	switch proxyType {
	case "socks4":
		return pc.CheckSOCKS4(proxy)
	case "socks5":
		return pc.CheckSOCKS5(proxy)
	case "http":
		return pc.CheckHTTP(proxy)
	default:
		return false
	}
}

// Fetches proxy lists from the provided URLs
func (pc *ProxyChecker) GetProxies(urls []string) []string {
	var allProxies []string
	for _, url := range urls {
		for attempt := 0; attempt <= pc.MaxRetries; attempt++ {
			if pc.CancelContext.Err() != nil {
				pc.Log("INFO", "Cancellation detected while fetching proxies")
				return nil
			}
			resp, err := http.Get(url)
			if err == nil && resp.StatusCode == http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				proxies := strings.Split(string(body), "\n")
				allProxies = append(allProxies, proxies...)
				break
			}
			time.Sleep(pc.RetryDelay)
		}
	}
	return allProxies
}

// Removes duplicate proxies from the list
func (pc *ProxyChecker) SanitizeProxies(proxies []string) []string {
	uniqueProxies := make(map[string]struct{})
	for _, proxy := range proxies {
		uniqueProxies[proxy] = struct{}{}
	}
	var sanitized []string
	for proxy := range uniqueProxies {
		sanitized = append(sanitized, proxy)
	}
	return sanitized
}

// Saves the sanitized proxies to a temporary file
func (pc *ProxyChecker) SaveProxiesToTempFile(proxyType string, proxies []string) string {
	tempDir := "temp_proxies"
	os.MkdirAll(tempDir, os.ModePerm)
	tempFile := fmt.Sprintf("%s/%s.txt", tempDir, proxyType)
	file, err := os.Create(tempFile)
	if err != nil {
		pc.Log("ERROR", fmt.Sprintf("Failed to save %s proxies to %s: %v", proxyType, tempFile, err))
		return ""
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, proxy := range proxies {
		fmt.Fprintln(writer, proxy)
	}
	writer.Flush()
	pc.Log("INFO", fmt.Sprintf("Saved sanitized %s proxies to %s", proxyType, tempFile))
	return tempFile
}

// Loads proxies from a temporary file
func (pc *ProxyChecker) LoadProxiesFromTempFile(tempFile string) []string {
	file, err := os.Open(tempFile)
	if err != nil {
		pc.Log("ERROR", fmt.Sprintf("Failed to load proxies from %s: %v", tempFile, err))
		return nil
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxies = append(proxies, scanner.Text())
	}
	pc.Log("INFO", fmt.Sprintf("Loaded %d proxies from %s", len(proxies), tempFile))
	return proxies
}

// Updates the progress bar in the terminal
func (pc *ProxyChecker) UpdateProgressBar(processed, total int) {
	progress := float64(processed) / float64(total)
	barLength := 50
	filled := int(progress * float64(barLength))
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", barLength-filled)
	fmt.Printf("\r[%s] %.0f%%", bar, progress*100)
}

// Checks the functionality of proxies and saves the working ones
func (pc *ProxyChecker) ProcessProxies(proxyType string, urls []string, maxChecks int) int {
	rawProxies := pc.GetProxies(urls)
	sanitized := pc.SanitizeProxies(rawProxies)
	tempPath := pc.SaveProxiesToTempFile(proxyType, sanitized)
	if tempPath == "" {
		return 0
	}

	proxies := pc.LoadProxiesFromTempFile(tempPath)
	total := len(proxies)
	if total == 0 {
		return 0
	}

	var wg sync.WaitGroup
	working := make(chan string, total)
	tokens := make(chan struct{}, maxChecks)
	processed := 0

	// Update progress bar periodically
	go func() {
		for processed < total {
			pc.UpdateProgressBar(processed, total)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			tokens <- struct{}{}
			defer func() { <-tokens }()

			if pc.CheckProxy(proxyType, p) {
				working <- p
			}

			processed++
		}(proxy)
	}

	wg.Wait()
	close(working)

	pc.UpdateProgressBar(processed, total)
	fmt.Println()

	var workingProxies []string
	for w := range working {
		workingProxies = append(workingProxies, w)
	}

	pc.SaveWorkingProxies(proxyType, workingProxies)
	return len(workingProxies)
}

// Saves the working proxies to a final file
func (pc *ProxyChecker) SaveWorkingProxies(proxyType string, proxies []string) {
	finalDir := "proxies"
	os.MkdirAll(finalDir, os.ModePerm)
	finalPath := fmt.Sprintf("%s/%s.txt", finalDir, strings.ToUpper(proxyType))

	file, err := os.Create(finalPath)
	if err != nil {
		pc.Log("ERROR", fmt.Sprintf("Failed to save %s proxies: %v", proxyType, err))
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, proxy := range proxies {
		fmt.Fprintln(writer, proxy)
	}
	writer.Flush()
	pc.Log("INFO", fmt.Sprintf("Saved %d working %s proxies to %s", len(proxies), proxyType, finalPath))
}

// Processes all proxy types and checks their functionality
func (pc *ProxyChecker) Run(maxChecks int) {
	for proxyType, urls := range pc.ProxyURLs {
		if pc.CancelContext.Err() != nil {
			break
		}
		pc.Log("INFO", fmt.Sprintf("\n%s", strings.Repeat("=", 40)))
		pc.Log("INFO", fmt.Sprintf("Processing %s proxies", strings.ToUpper(proxyType)))
		pc.Log("INFO", fmt.Sprintf("%s", strings.Repeat("=", 40)))
		pc.ProcessProxies(proxyType, urls, maxChecks)
	}
}

// Loads proxy URLs from a JSON file
func LoadURLsFromJSON(filePath string) map[string][]string {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error loading %s: %v", filePath, err)
	}

	var proxyURLs map[string][]string
	if err := json.Unmarshal(data, &proxyURLs); err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}
	return proxyURLs
}

func main() {
	maxChecks := flag.Int("maximum-checks", 5000, "Maximum number of concurrent proxy checks")
	flag.Parse()

	proxyURLs := LoadURLsFromJSON("urls.json")

	logCallback := func(msg string) {
		log.Println(msg)
	}
	progressCallback := func(progress int) {
		log.Printf("Progress: %d%%\n", progress)
	}

	checker := NewProxyChecker(proxyURLs, 5*time.Second, 0, 1*time.Second, 50, logCallback, progressCallback)
	defer checker.Cancel()

	log.Println("Starting proxy checking Press Ctrl+C to cancel")
	checker.Run(*maxChecks)
	log.Println("Done")
}
