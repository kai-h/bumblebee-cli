package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	githubOwner          = "perplexityai"
	githubRepo           = "bumblebee"
	catalogDirName       = "threat_intel"
	catalogMetaFile      = ".catalog_meta.json"
	catalogCheckInterval = 24 * time.Hour
)

type catalogMeta struct {
	Version   string    `json:"version"`    // full commit SHA
	CheckedAt time.Time `json:"checked_at"`
}

// catalogDataDir returns the platform-appropriate base directory for bumblebee data.
//
//   - Linux:   $XDG_DATA_HOME/bumblebee  (default ~/.local/share/bumblebee)
//   - macOS:   ~/Library/Application Support/bumblebee
//   - Windows: %LOCALAPPDATA%\bumblebee  (fallback %APPDATA%)
func catalogDataDir() (string, error) {
	var base string
	switch runtime.GOOS {
	case "linux":
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			base = xdg
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "share")
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, "Library", "Application Support")
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			base = d
		} else if d := os.Getenv("APPDATA"); d != "" {
			base = d
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, "AppData", "Local")
		}
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "bumblebee"), nil
}

// resolveCatalog returns the path to the threat intel catalog directory.
// If explicit is non-empty it is returned as-is with no network activity.
// Otherwise the default data directory is used: the catalog is downloaded on
// first use, and if a newer commit is available the user is prompted to update.
func resolveCatalog(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	dataDir, err := catalogDataDir()
	if err != nil {
		return "", fmt.Errorf("resolving data directory: %w", err)
	}

	catalogDir := filepath.Join(dataDir, catalogDirName)
	metaPath := filepath.Join(dataDir, catalogMetaFile)
	meta := readCatalogMeta(metaPath)
	exists := dirExists(catalogDir)

	// Skip the network check entirely if the catalog is fresh enough.
	if exists && meta != nil && time.Since(meta.CheckedAt) < catalogCheckInterval {
		return catalogDir, nil
	}

	// Overwritable single-line status — cleared before any multi-line output below.
	fmt.Fprintf(os.Stderr, "\rChecking threat intel catalog…")

	sha, err := fetchLatestCatalogSHA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\r\033[K")
		if exists {
			if meta != nil && meta.Version != "" {
				fmt.Fprintf(os.Stderr, "warning: catalog update check failed (%v); using %s\n", err, shortSHA(meta.Version))
			} else {
				fmt.Fprintf(os.Stderr, "warning: catalog update check failed: %v\n", err)
			}
			return catalogDir, nil
		}
		fmt.Fprintf(os.Stderr, "warning: no threat intel catalog found and GitHub is unreachable: %v\n", err)
		fmt.Fprintf(os.Stderr, "Scan will proceed without a threat intel catalog; results may be incomplete.\n")
		return "", nil
	}

	if !exists || meta == nil || meta.Version == "" {
		fmt.Fprintf(os.Stderr, "\r\033[K")
		fmt.Fprintf(os.Stderr, "Downloading threat intel catalog (%s)…\n", shortSHA(sha))
		if err := downloadCatalog(sha, dataDir, catalogDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: catalog download failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "Scan will proceed without a threat intel catalog; results may be incomplete.\n")
			return "", nil
		}
		saveCatalogMeta(metaPath, sha)
		fmt.Fprintf(os.Stderr, "Catalog installed at %s\n", catalogDir)
		return catalogDir, nil
	}

	if meta.Version == sha {
		fmt.Fprintf(os.Stderr, "\r\033[K")
		saveCatalogMeta(metaPath, sha) // refresh checked_at
		return catalogDir, nil
	}

	// Newer commit available — prompt interactively.
	fmt.Fprintf(os.Stderr, "\r\033[K")
	fmt.Fprintf(os.Stderr, "Threat intel update available: %s → %s\n", shortSHA(meta.Version), shortSHA(sha))
	if promptYN("Update now?") {
		fmt.Fprintf(os.Stderr, "Downloading…\n")
		if err := downloadCatalog(sha, dataDir, catalogDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: update failed: %v\n", err)
		} else {
			saveCatalogMeta(metaPath, sha)
			fmt.Fprintf(os.Stderr, "Catalog updated.\n")
		}
	} else {
		// Refresh checked_at so we don't re-prompt on every run until the next interval.
		saveCatalogMeta(metaPath, meta.Version)
	}

	return catalogDir, nil
}

// updateCatalog performs an unconditional check and update of the threat intel
// catalog. It is invoked by --update-catalog and exits after completion.
func updateCatalog() error {
	dataDir, err := catalogDataDir()
	if err != nil {
		return fmt.Errorf("resolving data directory: %w", err)
	}

	catalogDir := filepath.Join(dataDir, catalogDirName)
	metaPath := filepath.Join(dataDir, catalogMetaFile)
	meta := readCatalogMeta(metaPath)

	fmt.Fprintf(os.Stderr, "Checking threat intel catalog…\n")
	sha, err := fetchLatestCatalogSHA()
	if err != nil {
		return fmt.Errorf("checking GitHub: %w", err)
	}

	if meta != nil && meta.Version == sha && dirExists(catalogDir) {
		fmt.Fprintf(os.Stderr, "Already up to date (%s).\n", shortSHA(sha))
		saveCatalogMeta(metaPath, sha)
		return nil
	}

	if meta != nil && meta.Version != "" {
		fmt.Fprintf(os.Stderr, "Updating %s → %s…\n", shortSHA(meta.Version), shortSHA(sha))
	} else {
		fmt.Fprintf(os.Stderr, "Downloading threat intel catalog (%s)…\n", shortSHA(sha))
	}

	if err := downloadCatalog(sha, dataDir, catalogDir); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	saveCatalogMeta(metaPath, sha)
	fmt.Fprintf(os.Stderr, "Catalog updated at %s\n", catalogDir)
	return nil
}

// fetchLatestCatalogSHA returns the SHA of the most recent commit that touched
// the threat_intel/ directory on main.
func fetchLatestCatalogSHA() (string, error) {
	url := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/commits?path=threat_intel&sha=main&per_page=1",
		githubOwner, githubRepo,
	)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "bumblebee-cli")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	var commits []struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return "", fmt.Errorf("decoding GitHub response: %w", err)
	}
	if len(commits) == 0 {
		return "", fmt.Errorf("no commits found for threat_intel path")
	}
	return commits[0].SHA, nil
}

// downloadCatalog downloads the repo tarball at the given commit SHA, extracts
// the threat_intel/ directory from it, and installs it at catalogDir.
func downloadCatalog(sha, dataDir, catalogDir string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	// Download into dataDir so the temp file is on the same filesystem as
	// catalogDir, enabling an atomic os.Rename at the end.
	tmp, err := os.CreateTemp(dataDir, ".download-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	tarURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/tarball/%s", githubOwner, githubRepo, sha)
	if err := downloadFile(tarURL, tmp); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	// Extract into a sibling temp directory (same filesystem → fast rename).
	extractDir := filepath.Join(dataDir, ".extract-tmp")
	if err := os.RemoveAll(extractDir); err != nil {
		return fmt.Errorf("clearing extract dir: %w", err)
	}
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("creating extract dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := extractTarGz(tmpName, extractDir); err != nil {
		return fmt.Errorf("extracting archive: %w", err)
	}

	// Walk the extracted tree to find threat_intel/, matching the GUI's approach
	// (archive layout is not assumed to be stable).
	src, err := findNamedDir(extractDir, catalogDirName)
	if err != nil {
		return err
	}

	if err := os.RemoveAll(catalogDir); err != nil {
		return fmt.Errorf("removing old catalog: %w", err)
	}
	if err := os.Rename(src, catalogDir); err != nil {
		return fmt.Errorf("installing catalog: %w", err)
	}
	return nil
}

func downloadFile(url string, dst *os.File) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading: %s", resp.Status)
	}

	if _, err := io.Copy(dst, resp.Body); err != nil {
		return fmt.Errorf("writing download: %w", err)
	}
	return nil
}

// findNamedDir walks root and returns the path of the first directory named name.
func findNamedDir(root, name string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == name {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && found == "" {
		return "", fmt.Errorf("walking archive: %w", err)
	}
	if found == "" {
		return "", fmt.Errorf("%q directory not found in release archive", name)
	}
	return found, nil
}

func extractTarGz(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		target, ok := safeJoin(destDir, hdr.Name)
		if !ok {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode().Perm())
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			out.Close()
			if copyErr != nil {
				return copyErr
			}
		}
	}
	return nil
}

func extractZip(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	r, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return fmt.Errorf("zip reader: %w", err)
	}

	for _, zf := range r.File {
		target, ok := safeJoin(destDir, zf.Name)
		if !ok {
			continue
		}

		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, zf.Mode().Perm())
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

// safeJoin joins destDir with name, rejecting any path that would escape destDir.
func safeJoin(destDir, name string) (string, bool) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) ||
		clean == ".." ||
		strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return filepath.Join(destDir, clean), true
}

func readCatalogMeta(path string) *catalogMeta {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m catalogMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return &m
}

func saveCatalogMeta(path, version string) {
	m := catalogMeta{Version: version, CheckedAt: time.Now().UTC()}
	data, _ := json.Marshal(m)
	_ = os.WriteFile(path, data, 0600)
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// promptYN asks a yes/no question on stderr. Returns false without prompting
// when stdin is not a terminal (CI, pipes, redirects).
func promptYN(question string) bool {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line)) == "y"
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
