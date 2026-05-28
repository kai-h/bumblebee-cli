package main

import "sort"

// ScanPackage represents a detected dependency from bumblebee NDJSON output.
type ScanPackage struct {
	Ecosystem   string `json:"ecosystem"`
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	SourceFile  string `json:"source_file"`
	Confidence  string `json:"confidence"`
	ProjectPath string `json:"project_path"`
}

// ScanFinding represents a threat detection from bumblebee NDJSON output.
type ScanFinding struct {
	Ecosystem   string                 `json:"ecosystem"`
	PackageName string                 `json:"package_name"`
	Version     string                 `json:"version"`
	Severity    string                 `json:"severity"`
	FindingType string                 `json:"finding_type"`
	CatalogName string                 `json:"catalog_name"`
	Evidence    map[string]interface{} `json:"evidence"`
}

// rawRecord decodes any NDJSON line; field presence determines the record type.
// A line with "severity" or "finding_type" is a finding; "package_name" alone is a package.
type rawRecord struct {
	Ecosystem   string                 `json:"ecosystem"`
	PackageName string                 `json:"package_name"`
	Version     string                 `json:"version"`
	Severity    string                 `json:"severity"`
	FindingType string                 `json:"finding_type"`
	CatalogName string                 `json:"catalog_name"`
	Evidence    map[string]interface{} `json:"evidence"`
	SourceFile  string                 `json:"source_file"`
	Confidence  string                 `json:"confidence"`
	ProjectPath string                 `json:"project_path"`
}

// ScanResult holds the complete output of a scan.
type ScanResult struct {
	Packages []ScanPackage
	Findings []ScanFinding
}

// SortedFindings returns findings sorted by severity descending (critical first).
func (r *ScanResult) SortedFindings() []ScanFinding {
	findings := make([]ScanFinding, len(r.Findings))
	copy(findings, r.Findings)
	sort.Slice(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})
	return findings
}

// PackagesByEcosystem groups packages by their ecosystem, sorted alphabetically.
func (r *ScanResult) PackagesByEcosystem() ([]string, map[string][]ScanPackage) {
	m := make(map[string][]ScanPackage)
	for _, p := range r.Packages {
		m[p.Ecosystem] = append(m[p.Ecosystem], p)
	}
	ecosystems := make([]string, 0, len(m))
	for eco := range m {
		ecosystems = append(ecosystems, eco)
	}
	sort.Strings(ecosystems)
	return ecosystems, m
}

// severityRank maps severity strings to a numeric rank for sorting.
// Mirrors the GUI's severityRank logic.
func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
