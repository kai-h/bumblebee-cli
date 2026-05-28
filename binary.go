package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// resolveBinary finds the bumblebee binary to invoke. Resolution order:
//  1. Explicit --binary flag
//  2. bumblebee on PATH
//  3. bumblebee in the same directory as this binary
//  4. Previously auto-downloaded binary in the managed data directory
//  5. Download from the latest GitHub release
func resolveBinary(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if path, err := exec.LookPath("bumblebee"); err == nil {
		return path, nil
	}
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), binaryFilename())
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if path, err := managedBinaryPath(); err == nil {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return downloadBinary()
}

func binaryFilename() string {
	if runtime.GOOS == "windows" {
		return "bumblebee.exe"
	}
	return "bumblebee"
}

func managedBinaryPath() (string, error) {
	dataDir, err := catalogDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "bin", binaryFilename()), nil
}

func downloadBinary() (string, error) {
	dataDir, err := catalogDataDir()
	if err != nil {
		return "", fmt.Errorf("bumblebee binary not found; use --binary /path/to/bumblebee")
	}

	fmt.Fprintf(os.Stderr, "bumblebee not found — checking GitHub for latest release…\n")

	release, err := fetchLatestRelease()
	if err != nil {
		return "", fmt.Errorf(
			"bumblebee binary not found and GitHub is unreachable: %v\nUse --binary /path/to/bumblebee", err)
	}

	asset, ok := selectBinaryAsset(release.Assets)
	if !ok {
		return "", fmt.Errorf(
			"no bumblebee binary for %s/%s in release %s\nUse --binary /path/to/bumblebee",
			runtime.GOOS, runtime.GOARCH, release.TagName)
	}

	fmt.Fprintf(os.Stderr, "Downloading bumblebee %s (%s/%s)…\n", release.TagName, runtime.GOOS, runtime.GOARCH)

	binDir := filepath.Join(dataDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", fmt.Errorf("creating bin directory: %w", err)
	}

	tmp, err := os.CreateTemp(dataDir, ".binary-download-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := downloadFile(asset.BrowserDownloadURL, tmp); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()

	extractDir := filepath.Join(dataDir, ".binary-extract-tmp")
	if err := os.RemoveAll(extractDir); err != nil {
		return "", fmt.Errorf("clearing extract dir: %w", err)
	}
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return "", fmt.Errorf("creating extract dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := extractTarGz(tmpName, extractDir); err != nil {
		return "", fmt.Errorf("extracting binary: %w", err)
	}

	src, err := findNamedFile(extractDir, binaryFilename())
	if err != nil {
		return "", err
	}

	dest := filepath.Join(binDir, binaryFilename())
	_ = os.Remove(dest)
	if err := os.Rename(src, dest); err != nil {
		return "", fmt.Errorf("installing binary: %w", err)
	}
	if err := os.Chmod(dest, 0755); err != nil {
		return "", fmt.Errorf("chmod: %w", err)
	}

	fmt.Fprintf(os.Stderr, "bumblebee %s installed at %s\n", release.TagName, dest)
	return dest, nil
}

func fetchLatestRelease() (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", githubOwner, githubRepo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "bumblebee-cli")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	var r githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &r, nil
}

// selectBinaryAsset picks the release asset matching the current OS and arch.
// Asset names follow the pattern: bumblebee_{version}_{os}_{arch}.tar.gz
func selectBinaryAsset(assets []githubAsset) (githubAsset, bool) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	for _, a := range assets {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, goos) && strings.Contains(n, goarch) && isSupportedArchive(n) {
			return a, true
		}
	}
	return githubAsset{}, false
}

func isSupportedArchive(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip")
}

// findNamedFile walks root and returns the path of the first regular file named name.
func findNamedFile(root, name string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == name {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && found == "" {
		return "", fmt.Errorf("walking archive: %w", err)
	}
	if found == "" {
		return "", fmt.Errorf("%q not found in release archive", name)
	}
	return found, nil
}
