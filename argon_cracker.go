package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
)

/*
Cyclone's Argon2id Hash Cracker

sample hashes
$argon2id$v=19$m=65536,t=4,p=1$d2tycHJEYlBuenNEOUpqNg$pEXhocM661JmS3oRCR6MPQ:password
$argon2id$v=19$m=100000,t=4,p=1$cXVrNUdUVHI1SmN3RjcwNw$hMBzEYMGeblwwhj56bW6ig:password
$argon2id$v=19$m=65536,t=4,p=1$VWF5MkY2S3pYdm1nZm1HdQ$3zL8i47o4/l9rhLuDZE1oQ:passwords
$argon2id$v=19$m=65536,t=4,p=1$VWF5MkY2S3pYdm1nZm1HdQ$V3CVYSZuo4hAIgAPicV0NA:password1

version history
v0.1.0; 2024-01-03.1600; initial github release
*/

// clear screen function
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// thread-safe set data structure
type HashSet struct {
	m  map[string]string // store hash as key and encoded parameters as value
	mu sync.Mutex
}

// insert new element into set
func (s *HashSet) Add(hash, encodedParams string) {
	s.mu.Lock()
	s.m[hash] = encodedParams
	s.mu.Unlock()
}

// delete element from set
func (s *HashSet) Remove(hash string) {
	s.mu.Lock()
	delete(s.m, hash)
	s.mu.Unlock()
}

// return number of elements in set
func (s *HashSet) Length() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// parse argon2id parameters
func parseArgon2idParams(encodedParams string) (uint32, uint32, uint8, []byte, []byte, error) {
	parts := strings.Split(encodedParams, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, fmt.Errorf("invalid format: incorrect number of parts or not argon2id")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("error decoding salt: %v", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("error decoding hash: %v", err)
	}

	paramParts := strings.Split(parts[3], ",")
	if len(paramParts) != 3 {
		return 0, 0, 0, nil, nil, fmt.Errorf("invalid parameter format: expected 3 parameters")
	}

	memory, err := strconv.Atoi(strings.Split(paramParts[0], "=")[1])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("error parsing memory: %v", err)
	}

	time, err := strconv.Atoi(strings.Split(paramParts[1], "=")[1])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("error parsing time: %v", err)
	}

	parallelism, err := strconv.Atoi(strings.Split(paramParts[2], "=")[1])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("error parsing parallelism: %v", err)
	}

	return uint32(memory), uint32(time), uint8(parallelism), salt, hash, nil
}

// verify argon2id hashes
func verifyArgon2idHash(plaintext, hashLine string) bool {
	memory, time, parallelism, salt, expectedHash, err := parseArgon2idParams(hashLine)
	if err != nil {
		fmt.Println("Error parsing parameters:", err)
		return false
	}

	computedHash := argon2.IDKey([]byte(plaintext), salt, time, memory, parallelism, uint32(len(expectedHash)))
	return hex.EncodeToString(computedHash) == hex.EncodeToString(expectedHash)
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount, totalHashes, linesProcessed int) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	fmt.Fprintf(os.Stderr, "\nCracked:\t%d/%d\n", crackedCount, totalHashes)
	fmt.Fprintf(os.Stderr, "Hashrate:\t%.2f/s\n", linesPerSecond)
	//fmt.Fprintf(os.Stderr, "Total lines:\t%.2d\n", linesProcessed)
	fmt.Fprintf(os.Stderr, "Runtime:\t%02dh:%02dm:%02ds\n", hours, minutes, seconds)
}

// main function
func main() {
	// parse flags
	wordlistFileFlag := flag.String("w", "", "Wordlist file")
	hashFileFlag := flag.String("h", "", "Hash file")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Version number")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	flag.Parse()

	clearScreen()

	if *helpFlag {
		fmt.Fprintln(os.Stderr, "Cyclone's Argon2id Hash Cracker")
		fmt.Fprintln(os.Stderr, "\n./argon_crack.bin -h {hashfile} -w {wordlistfile}")
		//flag.Usage()
		os.Exit(0)
	}

	if *cycloneFlag {
		codedBy := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		codedByDecoded, _ := base64.StdEncoding.DecodeString(codedBy)
		fmt.Fprintln(os.Stderr, string(codedByDecoded))
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Fprintln(os.Stderr, "v0.1.0; 2024-01-03.1600")
		os.Exit(0)
	}

	if *wordlistFileFlag == "" || *hashFileFlag == "" {
		fmt.Fprintln(os.Stderr, "Both -w and -h flags are required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()
	crackedCount := 0
	linesProcessed := 0
	var linesProcessedMu sync.Mutex
	var crackedCountMu sync.Mutex

	// read all hashes into HashSet map
	uncrackedHashes := &HashSet{m: make(map[string]string)}
	hashFile, err := os.Open(*hashFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening hash file:", err)
		os.Exit(1)
	}
	defer hashFile.Close()

	hashScanner := bufio.NewScanner(hashFile)
	for hashScanner.Scan() {
		hashLine := hashScanner.Text()
		uncrackedHashes.Add(hashLine, hashLine)
	}
	totalHashes := uncrackedHashes.Length()

	// create a channel for each worker goroutine
	workerChannels := make([]chan string, runtime.NumCPU())
	for i := range workerChannels {
		workerChannels[i] = make(chan string, 1000) // buffer size
	}

	// welcome screen
	fmt.Fprintln(os.Stderr, " --------------------------------- ")
	fmt.Fprintln(os.Stderr, "| Cyclone's Argon2id Hash Cracker |")
	fmt.Fprintln(os.Stderr, " --------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Hash file:", *hashFileFlag)
	fmt.Fprintln(os.Stderr, "Total Hashes:", totalHashes)
	fmt.Fprintln(os.Stderr, "CPU Threads:", runtime.NumCPU())
	fmt.Fprintln(os.Stderr, "Wordlist:", *wordlistFileFlag)
	fmt.Fprintln(os.Stderr, "Working...\n")

	// goroutine to handle graceful shutdown
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+c pressed, quitting...")

		elapsedTime := time.Since(startTime)
		printStats(elapsedTime, crackedCount, totalHashes, linesProcessed)

		os.Exit(0)
	}()

	// start worker goroutines
	var wg sync.WaitGroup
	for _, ch := range workerChannels {
		wg.Add(1)
		go func(ch <-chan string) {
			defer wg.Done()
			for word := range ch {
				for hash, encodedParams := range uncrackedHashes.m {
					linesProcessedMu.Lock()
					linesProcessed++
					linesProcessedMu.Unlock()
					if verifyArgon2idHash(word, encodedParams) {
						fmt.Printf("%s:%s\n", hash, word)
						uncrackedHashes.Remove(hash)
						crackedCountMu.Lock()
						crackedCount++
						crackedCountMu.Unlock()
					}
				}
			}
		}(ch)
	}

	// start a single reader goroutine
	wg.Add(1)
	go func() {
		defer func() {
			for _, ch := range workerChannels {
				close(ch) // close all worker channels when done
			}
		}()
		defer wg.Done()

		wordlistFile, err := os.Open(*wordlistFileFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error opening wordlist file:", err)
			return
		}
		defer wordlistFile.Close()

		scanner := bufio.NewScanner(wordlistFile)
		workerIndex := 0
		for scanner.Scan() {
			word := strings.TrimRight(scanner.Text(), "\n")
			workerChannels[workerIndex] <- word
			workerIndex = (workerIndex + 1) % len(workerChannels) // round-robin
		}
	}()

	wg.Wait()

	elapsedTime := time.Since(startTime)
	printStats(elapsedTime, crackedCount, totalHashes, linesProcessed)
}

// end code