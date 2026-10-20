// Package state holds the result of one scan: what the dashboard, metrics and alerts show.
package state

import (
	"time"

	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/validate"
)

type State struct {
	At       time.Time           `json:"at"`
	Duration time.Duration       `json:"duration"`
	Err      string              `json:"error,omitempty"`
	Snap     *discovery.Snapshot `json:"snapshot,omitempty"`
	Certs    *certs.Assessment   `json:"certs,omitempty"`
	Findings []finding.Finding   `json:"findings"`
	Logs     []validate.LogStat  `json:"logs"`
	// IgnoredLogs are recurring errors hidden by ignore rules (shown, but not findings/alerts).
	IgnoredLogs []validate.LogStat `json:"ignoredLogs"`
}

// Counts returns finding counts by severity.
func (s *State) Counts() map[finding.Severity]int { return finding.Count(s.Findings) }
