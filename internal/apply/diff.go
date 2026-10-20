package apply

import (
	"fmt"
	"strings"
)

// UnifiedDiff returns a compact unified diff of two texts (3 lines of context).
func UnifiedDiff(name, a, b string) string {
	if a == b {
		return ""
	}
	x, y := splitLines(a), splitLines(b)
	ops := lcsOps(x, y)
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s (live)\n+++ %s (proposed)\n", name, name)
	const ctx = 3
	// Group ops into hunks.
	type op struct {
		kind byte // ' ', '-', '+'
		text string
		ai   int
		bi   int
	}
	var all []op
	ai, bi := 0, 0
	for _, o := range ops {
		switch o {
		case ' ':
			all = append(all, op{' ', x[ai], ai, bi})
			ai++
			bi++
		case '-':
			all = append(all, op{'-', x[ai], ai, bi})
			ai++
		case '+':
			all = append(all, op{'+', y[bi], ai, bi})
			bi++
		}
	}
	for i := 0; i < len(all); {
		if all[i].kind == ' ' {
			i++
			continue
		}
		start := max(0, i-ctx)
		end := i
		for end < len(all) {
			if all[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(all) && all[run].kind == ' ' {
				run++
			}
			if run-end > 2*ctx || run == len(all) {
				end = min(len(all), end+ctx)
				break
			}
			end = run
		}
		aCount, bCount := 0, 0
		for _, o := range all[start:end] {
			if o.kind != '+' {
				aCount++
			}
			if o.kind != '-' {
				bCount++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", all[start].ai+1, aCount, all[start].bi+1, bCount)
		for _, o := range all[start:end] {
			out.WriteByte(o.kind)
			out.WriteString(o.text)
			out.WriteByte('\n')
		}
		i = end
	}
	return out.String()
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lcsOps returns an edit script (' ', '-', '+') via a longest-common-subsequence table. Inputs
// here are small manifests, so the quadratic table is fine.
func lcsOps(x, y []string) []byte {
	n, m := len(x), len(y)
	t := make([][]int, n+1)
	for i := range t {
		t[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	var ops []byte
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			ops = append(ops, ' ')
			i++
			j++
		case t[i+1][j] >= t[i][j+1]:
			ops = append(ops, '-')
			i++
		default:
			ops = append(ops, '+')
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, '-')
	}
	for ; j < m; j++ {
		ops = append(ops, '+')
	}
	return ops
}
