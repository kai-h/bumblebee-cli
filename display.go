package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Severity colors match the macOS GUI's severityColor values.
var (
	criticalBg = lipgloss.Color("#FF3B30") // red
	highBg     = lipgloss.Color("#FF9500") // orange
	mediumBg   = lipgloss.Color("#D9A600") // dark yellow (matches GUI rgb(0.85,0.65,0))
	lowBg      = lipgloss.Color("#007AFF") // blue
	unknownBg  = lipgloss.Color("#888888")

	cleanColor = lipgloss.Color("#30D158") // green
	dimColor   = lipgloss.Color("#888888")
)

var (
	boldStyle    = lipgloss.NewStyle().Bold(true)
	dimStyle     = lipgloss.NewStyle().Foreground(dimColor)
	cleanStyle   = lipgloss.NewStyle().Foreground(cleanColor).Bold(true)
	findingStyle = lipgloss.NewStyle().Foreground(highBg).Bold(true)
)

func severityBadge(severity string) string {
	var bg lipgloss.Color
	switch severity {
	case "critical":
		bg = criticalBg
	case "high":
		bg = highBg
	case "medium":
		bg = mediumBg
	case "low":
		bg = lowBg
	default:
		bg = unknownBg
	}
	return lipgloss.NewStyle().
		Background(bg).
		Foreground(lipgloss.Color("#FFFFFF")).
		Padding(0, 1).
		Bold(true).
		Render(strings.ToUpper(severity))
}

// displayResults prints the full formatted scan output, matching the GUI's
// section order: findings first (sorted by severity), then packages by ecosystem.
func displayResults(result *ScanResult) {
	if len(result.Findings) == 0 && len(result.Packages) == 0 {
		fmt.Println("No results.")
		return
	}

	// ── Findings ────────────────────────────────────────────────────────────
	if len(result.Findings) > 0 {
		fmt.Println(boldStyle.Render(fmt.Sprintf("Findings (%d)", len(result.Findings))))
		fmt.Println()

		for _, f := range result.SortedFindings() {
			nameVer := f.PackageName
			if f.Version != "" {
				nameVer += "  " + dimStyle.Render(f.Version)
			}
			fmt.Printf("  %s  %s\n", severityBadge(f.Severity), nameVer)

			// ecosystem · catalog · finding_type
			var meta []string
			if f.Ecosystem != "" {
				meta = append(meta, f.Ecosystem)
			}
			if f.CatalogName != "" {
				meta = append(meta, f.CatalogName)
			}
			if f.FindingType != "" {
				meta = append(meta, f.FindingType)
			}
			if len(meta) > 0 {
				fmt.Printf("        %s\n", dimStyle.Render(strings.Join(meta, " · ")))
			}

			if len(f.Evidence) > 0 {
				var parts []string
				for k, v := range f.Evidence {
					parts = append(parts, fmt.Sprintf("%s: %v", k, v))
				}
				sort.Strings(parts)
				fmt.Printf("        %s\n", dimStyle.Render(strings.Join(parts, "  ·  ")))
			}

			fmt.Println()
		}
	}

	// ── Packages ────────────────────────────────────────────────────────────
	if len(result.Packages) > 0 {
		fmt.Println(boldStyle.Render(fmt.Sprintf("Packages (%d)", len(result.Packages))))
		fmt.Println()

		ecosystems, byEco := result.PackagesByEcosystem()
		for _, eco := range ecosystems {
			pkgs := byEco[eco]
			fmt.Printf("  %s\n", boldStyle.Render(fmt.Sprintf("%s (%d)", eco, len(pkgs))))

			if len(result.Findings) > 0 {
				display := pkgs
				if len(display) > 100 {
					display = display[:100]
				}

				for _, p := range display {
					var meta []string
					if p.Version != "" {
						meta = append(meta, p.Version)
					}
					if p.SourceFile != "" {
						meta = append(meta, p.SourceFile)
					}

					if len(meta) > 0 {
						fmt.Printf("    %s  %s\n", p.PackageName, dimStyle.Render(strings.Join(meta, " · ")))
					} else {
						fmt.Printf("    %s\n", p.PackageName)
					}

					// Confidence labels match GUI tooltip text exactly.
					switch p.Confidence {
					case "medium":
						fmt.Printf("      %s\n", dimStyle.Render("medium confidence — version inferred from spec or tag, not confirmed by lockfile"))
					case "low":
						fmt.Printf("      %s\n", dimStyle.Render("low confidence — detected from config reference only, not confirmed as installed"))
					}
				}

				if len(pkgs) > 100 {
					fmt.Printf("    %s\n", dimStyle.Render(fmt.Sprintf("… and %d more", len(pkgs)-100)))
				}
			}

			fmt.Println()
		}
	}

	// ── Summary line — mirrors GUI status message format ────────────────────
	if len(result.Findings) > 0 {
		fmt.Printf("%s  ·  %d package(s)\n",
			findingStyle.Render(fmt.Sprintf("%d finding(s)", len(result.Findings))),
			len(result.Packages),
		)
	} else {
		fmt.Println(cleanStyle.Render(fmt.Sprintf("Clean — %d package(s) scanned, no findings", len(result.Packages))))
	}
}
