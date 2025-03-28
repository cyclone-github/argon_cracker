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
v0.1.1; 2024-01-04.1930;
	fixed https://github.com/cyclone-github/argon_cracker/issues/2
	added -t flag to allow user to specify CPU threads
	added hash sanity checks
	cleaned up & refactored code
v0.1.2; 2025-03-28;
	fixed race condition: https://github.com/cyclone-github/argon_cracker/issues/5
	fixed close on closed channel: https://github.com/cyclone-github/argon_cracker/issues/6

TODO:
Implement codebase from yescrypt_crack (safe concurrent goroutines)
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

// check if hash line is a valid argon2id
func isValidArgon2idHash(hashLine string) bool {
	parts := strings.Split(hashLine, "$")
	if len(parts) < 6 || parts[1] != "argon2id" {
		return false
	}
	return true
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

// set CPU threads
func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > 2*runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
}

// read all hashes into a HashSet
func readHashes(hashFilePath string) (*HashSet, int, int, error) {
	uncrackedHashes := &HashSet{m: make(map[string]string)}
	validHashCount := 0
	invalidHashCount := 0

	hashFile, err := os.Open(hashFilePath)
	if err != nil {
		return nil, 0, 0, err
	}
	defer hashFile.Close()

	hashScanner := bufio.NewScanner(hashFile)
	for hashScanner.Scan() {
		hashLine := hashScanner.Text()
		if isValidArgon2idHash(hashLine) {
			uncrackedHashes.Add(hashLine, hashLine)
			validHashCount++
		} else {
			invalidHashCount++
		}
	}

	return uncrackedHashes, validHashCount, invalidHashCount, nil
}

// print welcome screen
func printWelcomeScreen(hashFileFlag, wordlistFileFlag *string, validHashCount, invalidHashCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " --------------------------------- ")
	fmt.Fprintln(os.Stderr, "| Cyclone's Argon2id Hash Cracker |")
	fmt.Fprintln(os.Stderr, " --------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Hash file:\t%s\n", *hashFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Hashes:\t%d\n", validHashCount)
	fmt.Fprintf(os.Stderr, "Invalid Hashes:\t%d\n", invalidHashCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)
	fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	fmt.Fprintln(os.Stderr, "Working...\n ")
}

// handle graceful shutdown if ctrl+c is pressed
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+c pressed, quitting...")
		close(stopChan)
	}()
}

// stop channel sync
var stopOnce sync.Once

func closeStopChan(stopChan chan struct{}) {
	time.Sleep(500 * time.Millisecond) // hacky way to keep from closing early until code base from yescrypt_crack can be implemented
	stopOnce.Do(func() { close(stopChan) })
}

// hash cracking worker
func startWorker(ch <-chan string, stopChan chan struct{}, uncrackedHashes *HashSet, crackedCountCh chan int, linesProcessedCh chan int) {
	for {
		select {
		case <-stopChan:
			return
		case word, ok := <-ch:
			if !ok {
				closeStopChan(stopChan) // channel closed, no more words to process
				return
			}
			uncrackedHashes.mu.Lock()
			hashesCopy := make(map[string]string, len(uncrackedHashes.m))
			for hash, encodedParams := range uncrackedHashes.m {
				hashesCopy[hash] = encodedParams
			}
			uncrackedHashes.mu.Unlock()

			for hash, encodedParams := range hashesCopy {
				if verifyArgon2idHash(word, encodedParams) {
					fmt.Printf("%s:%s\n", hash, word)
					uncrackedHashes.Remove(hash)
					crackedCountCh <- 1 // increment cracked count
					if uncrackedHashes.Length() == 0 {
						closeStopChan(stopChan) // no more hashes to process
						return
					}
				}
			}
			linesProcessedCh <- 1 // increment lines processed
		}
	}
}

// monitor status
func monitorAndPrintResults(crackedCountCh, linesProcessedCh <-chan int, stopChan <-chan struct{}, startTime time.Time, validHashCount int, wg *sync.WaitGroup) {
	crackedCount := 0
	linesProcessed := 0

	for {
		select {
		case <-crackedCountCh:
			crackedCount++
		case <-linesProcessedCh:
			linesProcessed++
		case <-stopChan:
			elapsedTime := time.Since(startTime)
			printStats(elapsedTime, crackedCount, validHashCount, linesProcessed)
			wg.Done()
			return
		}
	}
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount, validHashCount, linesProcessed int) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	fmt.Fprintf(os.Stderr, "\nCracked:\t%d/%d\n", crackedCount, validHashCount)
	fmt.Fprintf(os.Stderr, "Hashrate:\t%.2f h/s\n", linesPerSecond)
	fmt.Fprintf(os.Stderr, "Runtime:\t%02dh:%02dm:%02ds\n", hours, minutes, seconds)
	os.Exit(0) // make sure program exits
}

// main function
func main() {
	wordlistFileFlag := flag.String("w", "", "Wordlist file")
	hashFileFlag := flag.String("h", "", "Hash file")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	flag.Parse()

	clearScreen()

	// sanity checks for cli arguments
	if *helpFlag {
		fmt.Fprintln(os.Stderr, "Cyclone's Argon2id Hash Cracker")
		fmt.Fprintln(os.Stderr, "\nUsage example:")
		fmt.Fprintln(os.Stderr, "\n./argon_cracker -h {hash file} -w {wordlist file} -t {CPU threads to use (optional)}\n ")
		flag.Usage()
		os.Exit(0)
	}

	if *cycloneFlag {
		codedBy := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		codedByDecoded, _ := base64.StdEncoding.DecodeString(codedBy)
		fmt.Fprintln(os.Stderr, string(codedByDecoded))
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Fprintln(os.Stderr, "v0.1.2; 2025-03-28")
		os.Exit(0)
	}

	if *wordlistFileFlag == "" || *hashFileFlag == "" {
		fmt.Fprintln(os.Stderr, "Both -w and -h flags are required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	// set CPU threads
	numThreads := setNumThreads(*threadFlag)

	// channels / variables
	crackedCountCh := make(chan int, 1)
	linesProcessedCh := make(chan int, 1)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// read hashes into HashSet map
	uncrackedHashes, validHashCount, invalidHashCount, err := readHashes(*hashFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading hash file:", err)
		os.Exit(1)
	}

	// create channel for each worker goroutine
	workerChannels := make([]chan string, numThreads)
	for i := range workerChannels {
		workerChannels[i] = make(chan string, 100) // buffer size
	}

	// print welcome screen
	printWelcomeScreen(hashFileFlag, wordlistFileFlag, validHashCount, invalidHashCount, numThreads)

	// goroutine to watch for ctrl+c
	handleGracefulShutdown(stopChan)

	// start worker goroutines
	for _, ch := range workerChannels {
		wg.Add(1)
		go func(ch <-chan string) {
			defer wg.Done()
			startWorker(ch, stopChan, uncrackedHashes, crackedCountCh, linesProcessedCh)
		}(ch)
	}

	// reader goroutine
	// refactoring this code causes goroutine panics, so leaving in main func for now
	wg.Add(1)
	go func() {
		defer func() {
			for _, ch := range workerChannels {
				close(ch) // close all worker channels when done
				return
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

	// monitor status of workers
	wg.Add(1)
	go monitorAndPrintResults(crackedCountCh, linesProcessedCh, stopChan, startTime, validHashCount, &wg)

	// wait for all goroutines to finish
	wg.Wait()

}

// end code
