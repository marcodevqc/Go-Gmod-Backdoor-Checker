package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)


// CLI colors/styles
var (
	headerStyle  = color.New(color.FgHiWhite, color.Bold)
	errorStyle   = color.New(color.FgRed, color.Bold)
	warnStyle    = color.New(color.FgYellow)
	successStyle = color.New(color.FgGreen, color.Bold)
	fileStyle    = color.New(color.FgCyan)
	lineStyle    = color.New(color.FgHiBlue)
	patternStyle = color.New(color.FgMagenta)
)

// Stats tracks scan progress
type Stats struct {
	FilesScanned    int
	FindingsCount   int
	StartTime       time.Time
	PatternCount    int
	sync.Mutex
}

func (s *Stats) IncrementFiles() {
	s.Lock()
	s.FilesScanned++
	s.Unlock()
}

func (s *Stats) AddFindings(n int) {
	s.Lock()
	s.FindingsCount += n
	s.Unlock()
}

// printProgress shows scan progress every second
func (s *Stats) printProgress() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.Lock()
		fmt.Printf("\rScanning... %d files processed, %d findings so far (%.1fs elapsed)",
			s.FilesScanned, s.FindingsCount, time.Since(s.StartTime).Seconds())
		s.Unlock()
	}
}

type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Pattern string `json:"pattern"`
	Snippet string `json:"snippet"`
}

// Generic named patterns (populated from patterns JSON at startup).
var patterns = map[string]*regexp.Regexp{}

// filePatterns stores compiled regexes and human-readable defs per-extension
type PatternDef struct {
	Re  *regexp.Regexp
	Def string
}

var filePatterns = map[string][]PatternDef{}

// NOTE: old text-file loader removed; patterns are now loaded from a single JSON file via loadPatternsJSON.
// loadPatternsJSON loads both generic and per-extension patterns from a single JSON file.
// Expected schema:
// {
//   "generic": [{"name": "RunString", "pattern": "\\b(RunString|CompileString)\\b"}, ...],
//   "per_extension": { ".lua": [{"pattern": "RunString", "description": "Code Execution"}, ...] }
// }
func loadPatternsJSON(pth string) error {
	data, err := ioutil.ReadFile(pth)
	if err != nil {
		return err
	}
	var doc struct {
		Generic      []struct{
			Name    string `json:"name"`
			Pattern string `json:"pattern"`
		} `json:"generic"`
		PerExtension map[string][]struct{
			Pattern     string `json:"pattern"`
			Description string `json:"description"`
		} `json:"per_extension"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}

	// compile generic patterns
	for _, g := range doc.Generic {
		if g.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(g.Pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping invalid generic pattern %q: %v\n", g.Pattern, err)
			continue
		}
		patterns[g.Name] = re
	}

	// compile per-extension patterns
	for ext, arr := range doc.PerExtension {
		for _, e := range arr {
			if e.Pattern == "" {
				continue
			}
			re, err := regexp.Compile(e.Pattern)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skipping invalid per-extension pattern for %s: %q: %v\n", ext, e.Pattern, err)
				continue
			}
			filePatterns[ext] = append(filePatterns[ext], PatternDef{Re: re, Def: e.Description})
		}
	}
	return nil
}

func isText(b []byte) bool {
	// A simple heuristic: if there are NUL bytes, treat as binary.
	return !bytes.Contains(b, []byte{0})
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var ent float64
	l := float64(len(s))
	for _, f := range freq {
		p := f / l
		ent += -p * math.Log2(p)
	}
	return ent
}

// RE2 (Go regexp) doesn't support backreferences (e.g. \1). Use a simpler
// approximation that matches a long quoted string (may allow mismatched quotes).
var longQuotedRE = regexp.MustCompile(`(["'])([^"']{30,})["']`)

var base64LongRE = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`)
// avoid non-capturing groups (?:...) which RE2 does not support; use a normal group
var charCodeRE = regexp.MustCompile(`\b([0-9]{2,3}(,[0-9]{2,3})*)\b`)

func scanFile(path string) ([]Finding, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	findings := []Finding{}
	ext := strings.ToLower(filepath.Ext(path))

	if isText(data) {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)

			// file-specific pattern checks
			if defs, ok := filePatterns[ext]; ok {
				for _, pd := range defs {
					if pd.Re.MatchString(line) {
						findings = append(findings, Finding{File: path, Line: lineNo, Pattern: pd.Def, Snippet: trimmed})
						// if CharCode-like, try to decode and include decoded snippet
						if strings.Contains(strings.ToLower(pd.Def), "charcode") || strings.Contains(strings.ToLower(pd.Def), "decimal") {
							dec := decodeCharCodes(line)
							if dec != "" {
								findings = append(findings, Finding{File: path, Line: lineNo, Pattern: "Decoded CharCode", Snippet: snippet(dec)})
							}
						}
					}
				}
			}

			// generic heuristics
			for name, re := range patterns {
				if re.MatchString(line) {
					findings = append(findings, Finding{File: path, Line: lineNo, Pattern: name, Snippet: trimmed})
				}
			}

			// entropy on long quoted strings
			for _, match := range longQuotedRE.FindAllStringSubmatch(line, -1) {
				if len(match) >= 3 {
					content := match[2]
					ent := shannonEntropy(content)
					if ent > 4.0 { // heuristic threshold
						findings = append(findings, Finding{File: path, Line: lineNo, Pattern: "High-entropy string", Snippet: snippet(content)})
						// try base64 decode
						tryBase64Decode(content, &findings, path, lineNo)
					}
				}
			}

			// attempt to detect inline long base64 and decode
			for _, b64 := range base64LongRE.FindAllString(line, -1) {
				tryBase64Decode(b64, &findings, path, lineNo)
			}
		}
	} else {
		// For binaries, search for long base64/hex sequences in the whole blob
		text := string(data)
		if patterns["Encrypted-looking"].MatchString(text) || base64LongRE.MatchString(text) {
			findings = append(findings, Finding{File: path, Pattern: "Embedded base64-like data", Snippet: "(binary file contains long base64-like substrings)"})
		}
		if patterns["HexBlob"].MatchString(text) {
			findings = append(findings, Finding{File: path, Pattern: "Embedded hex blob", Snippet: "(binary file contains long hex-like substrings)"})
		}
	}
	return findings, nil
}

func decodeCharCodes(line string) string {
	// find sequences like 97,98,99 and convert to text where possible
	var out strings.Builder
	found := false
	for _, match := range charCodeRE.FindAllStringSubmatch(line, -1) {
		if len(match) < 2 {
			continue
		}
		seq := match[1]
		parts := strings.Split(seq, ",")
		for _, p := range parts {
			v, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || v < 0 || v > 255 {
				out.WriteString("[Invalid]")
				continue
			}
			out.WriteByte(byte(v))
			found = true
		}
		out.WriteString(" ")
	}
	if !found {
		return ""
	}
	return strings.TrimSpace(out.String())
}

func tryBase64Decode(s string, findings *[]Finding, path string, lineNo int) {
	// strip non-base64 padding characters
	s = strings.TrimSpace(s)
	// Try Std decoding
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		// if decoded looks like text, rescan minimal
		if isText(decoded) {
			txt := string(decoded)
			// add a finding with a short snippet of decoded text
			*findings = append(*findings, Finding{File: path, Line: lineNo, Pattern: "Base64 decoded", Snippet: snippet(txt)})
		}
	}
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func scanDir(root string) ([]Finding, error) {
	// Concurrent scanner: walk the tree and push file paths to workers which run scanFile
	out := []Finding{}
	files := make(chan string, 256)
	results := make(chan []Finding, 256)
	stats := &Stats{StartTime: time.Now()}

	// start progress reporting
	done := make(chan struct{})
	go func() {
		stats.printProgress()
		<-done
	}()

	// count patterns
	stats.PatternCount = len(patterns)
	for _, ext := range filePatterns {
		stats.PatternCount += len(ext)
	}

	// spawn workers
	workers := runtime.NumCPU()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range files {
				f, err := scanFile(p)
				stats.IncrementFiles()
				if err != nil {
					// skip unreadable files
					continue
				}
				if len(f) > 0 {
					stats.AddFindings(len(f))
					results <- f
				}
			}
		}()
	}

	// walk the directory in a goroutine so we can feed files to workers
	var walkErr error
	go func() {
		walkErr = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				// skip files we can't access
				return nil
			}
			if info.IsDir() {
				return nil
			}
			files <- path
			return nil
		})
		close(files)
	}()

	// close results when workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		out = append(out, r...)
	}

	if os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("path does not exist: %s", root)
	}

	// stop progress reporting
	close(done)
	fmt.Println() // clear progress line

	// print summary
	elapsed := time.Since(stats.StartTime)
	headerStyle.Println("\nScan Summary")
	fmt.Printf("├─ Time: %.2f seconds\n", elapsed.Seconds())
	fmt.Printf("├─ Files processed: %d\n", stats.FilesScanned)
	fmt.Printf("├─ Active patterns: %d\n", stats.PatternCount)
	fmt.Printf("└─ Findings: %d\n\n", len(out))

	return out, walkErr
}

func usage() {
	headerStyle.Fprintf(os.Stderr, "GMod Backdoor Scanner\n")
	fmt.Fprintln(os.Stderr, "Scan Garry's Mod addons for suspicious patterns and potential backdoors.\n")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  scanner [options]\n")
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  -path string")
	fmt.Fprintln(os.Stderr, "        Path to addons folder (default \"addons\")")
	fmt.Fprintln(os.Stderr, "  -json string")
	fmt.Fprintln(os.Stderr, "        Write findings to JSON file\n")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  scanner -path ./addons")
	fmt.Fprintln(os.Stderr, "  scanner -path ../garrysmod/addons -json findings.json")
}

func main() {
	path := flag.String("path", "addons", "path to addons folder")
	jsonOut := flag.String("json", "", "optional JSON output file")
	flag.Parse()

	// If addons folder missing, proceed but return helpful error
	if _, err := os.Stat(*path); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "path not found: %s\n", *path)
		os.Exit(2)
	}

	// attempt to load patterns from ./patterns/patterns.json (non-fatal)
	_ = loadPatternsJSON(filepath.Join("patterns", "patterns.json"))

	findings, err := scanDir(*path)
	if err != nil {
		errorStyle.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut != "" {
		b, _ := json.MarshalIndent(findings, "", "  ")
		if err := ioutil.WriteFile(*jsonOut, b, 0644); err != nil {
			errorStyle.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
		successStyle.Printf("Wrote %d findings to %s\n", len(findings), *jsonOut)
		return
	}

	// Print findings human-readably
	if len(findings) == 0 {
		successStyle.Println("No suspicious patterns found.")
		return
	}

	headerStyle.Printf("\nFindings (%d total):\n", len(findings))
	for _, f := range findings {
		if f.Line > 0 {
			fileStyle.Printf("%s", f.File)
			fmt.Print(":")
			lineStyle.Printf("%d", f.Line)
			fmt.Print(" — ")
			patternStyle.Printf("%s\n", f.Pattern)
			fmt.Printf("  %s\n", f.Snippet)
		} else {
			fileStyle.Printf("%s", f.File)
			fmt.Print(" — ")
			patternStyle.Printf("%s\n", f.Pattern)
			fmt.Printf("  %s\n", f.Snippet)
		}
	}
}
