package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		binaryFlag      = flag.String("binary", "", "path to bumblebee binary (default: searches PATH then directory of this binary)")
		profile         = flag.String("profile", "project", "scan profile: project, baseline, or deep")
		root            = flag.String("root", "", "root directory to scan (required for project and deep profiles)")
		catalogPath     = flag.String("catalog", "", "path to threat intel catalog directory")
		doUpdateCatalog = flag.Bool("update-catalog", false, "update threat intel catalog from GitHub and exit")
		doVersion       = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: bumblebee-cli [flags]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *doVersion {
		fmt.Println(version)
		return
	}

	if *doUpdateCatalog {
		if err := updateCatalog(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	binaryPath, err := resolveBinary(*binaryFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *profile != "baseline" && *root == "" {
		fmt.Fprintf(os.Stderr, "Error: --root is required for project and deep profiles\n\n")
		flag.Usage()
		os.Exit(1)
	}

	catalogDir, err := resolveCatalog(*catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result, err := runScan(binaryPath, *profile, *root, catalogDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}

	// Clear the progress line.
	fmt.Fprint(os.Stderr, "\r\033[K")

	displayResults(result)

	// Exit 2 signals findings were detected, allowing shell scripts to distinguish
	// "scan succeeded, findings present" from "scan failed" (exit 1).
	if len(result.Findings) > 0 {
		os.Exit(2)
	}
}

