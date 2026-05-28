package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// runScan executes the bumblebee binary, streams its NDJSON stdout, and
// returns the accumulated results. Progress is written to stderr in place.
//
// bumblebee writes JSON diagnostic records to its own stderr. We pipe that
// separately and suppress info/debug-level diagnostics so they don't corrupt
// the progress display. warn/error-level records and any non-JSON stderr
// output are forwarded to the user.
func runScan(binaryPath, profile, root, catalogPath string) (*ScanResult, error) {
	args := []string{"scan", "--profile", profile}
	if root != "" {
		args = append(args, "--root", root)
	}
	if catalogPath != "" {
		args = append(args, "--exposure-catalog", catalogPath)
	}

	cmd := exec.Command(binaryPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start bumblebee: %w", err)
	}

	// Drain bumblebee's stderr concurrently. JSON info/debug diagnostics are
	// discarded; everything else (warn/error JSON or plain text) is printed on
	// a clean line so it doesn't corrupt the progress indicator.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			var rec struct {
				Level string `json:"level"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err == nil {
				if rec.Level == "info" || rec.Level == "debug" {
					continue
				}
			}
			// Clear the progress line before printing, then restore the cursor.
			fmt.Fprintf(os.Stderr, "\r\033[K%s\n", line)
		}
	}()

	result := &ScanResult{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var raw rawRecord
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		if raw.Severity != "" || raw.FindingType != "" {
			result.Findings = append(result.Findings, ScanFinding{
				Ecosystem:   raw.Ecosystem,
				PackageName: raw.PackageName,
				Version:     raw.Version,
				Severity:    raw.Severity,
				FindingType: raw.FindingType,
				CatalogName: raw.CatalogName,
				Evidence:    raw.Evidence,
			})
		} else if raw.PackageName != "" {
			result.Packages = append(result.Packages, ScanPackage{
				Ecosystem:   raw.Ecosystem,
				PackageName: raw.PackageName,
				Version:     raw.Version,
				SourceFile:  raw.SourceFile,
				Confidence:  raw.Confidence,
				ProjectPath: raw.ProjectPath,
			})
		}

		printProgress(len(result.Packages), len(result.Findings))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading bumblebee output: %w", err)
	}

	wg.Wait()
	// Non-zero exit is expected when findings are present; not treated as fatal.
	_ = cmd.Wait()

	return result, nil
}

func printProgress(packages, findings int) {
	if findings > 0 {
		fmt.Fprintf(os.Stderr, "\rScanning… %d package(s) found, %d finding(s)    ", packages, findings)
	} else {
		fmt.Fprintf(os.Stderr, "\rScanning… %d package(s) found    ", packages)
	}
}
