// Package finding is the shared shape of every observation the app reports: certificate
// checks, config validation and runtime checks all become Findings, which drive the dashboard,
// metrics and alerts.
package finding

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Rank orders severities: info < warning < critical.
func Rank(s Severity) int {
	switch s {
	case Critical:
		return 2
	case Warning:
		return 1
	}
	return 0
}

// AtLeast reports whether s is at or above min.
func AtLeast(s, min Severity) bool { return Rank(s) >= Rank(min) }

type Finding struct {
	Severity Severity `json:"severity"`
	// Code is stable and machine-readable; it labels metrics and dedupes alerts.
	Code    string `json:"code"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
	// Setting is the settings-model key the finding points at, if any.
	Setting string `json:"setting,omitempty"`
	// Source is the check family: certs, config, runtime, logs.
	Source string `json:"source,omitempty"`
}

// Max returns the highest severity in fs (info when empty).
func Max(fs []Finding) Severity {
	m := Info
	for _, f := range fs {
		if Rank(f.Severity) > Rank(m) {
			m = f.Severity
		}
	}
	return m
}

// Count returns how many findings have each severity.
func Count(fs []Finding) map[Severity]int {
	out := map[Severity]int{Info: 0, Warning: 0, Critical: 0}
	for _, f := range fs {
		out[f.Severity]++
	}
	return out
}
