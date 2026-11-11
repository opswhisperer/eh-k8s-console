package discovery

import "testing"

func TestExpandVars(t *testing.T) {
	env := map[string]envVal{
		"HOST":   {value: "192.0.2.10", cmKeys: []string{"mgmtTarget"}, known: true, tracks: "mgmtTarget"},
		"LIT":    {value: "lit", known: true},
		"SECRET": {known: false},
	}
	for _, tc := range []struct {
		in, want       string
		refs, resolved bool
		tracks         string
	}{
		{"192.0.2.10", "192.0.2.10", false, true, ""},
		{"$(HOST)", "192.0.2.10", true, true, "mgmtTarget"},
		{"$(HOST):443", "192.0.2.10:443", true, true, ""},
		{"$(LIT)", "lit", true, true, ""},
		{"$$(HOST)", "$(HOST)", false, true, ""},
		{"$(NOPE)", "$(NOPE)", true, false, ""},
		{"$(SECRET)", "$(SECRET)", true, false, ""},
		{"$(HOST", "$(HOST", false, true, ""},
		{"a$b$", "a$b$", false, true, ""},
	} {
		x := expandVars(tc.in, env)
		if x.Value != tc.want || x.HasRefs != tc.refs || x.Resolved != tc.resolved || x.Tracks != tc.tracks {
			t.Errorf("%q: got %+v, want value=%q refs=%v resolved=%v tracks=%q", tc.in, x, tc.want, tc.refs, tc.resolved, tc.tracks)
		}
	}
}
