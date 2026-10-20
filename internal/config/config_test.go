package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The shipped configs must parse strictly (unknown keys are errors) and validate.
func TestShippedConfigsLoad(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	paths := []string{"deploy/base/config.yaml", "config/example.yaml"}
	examples, _ := filepath.Glob(filepath.Join(root, "deploy", "examples", "*", "config.yaml"))
	for _, e := range examples {
		rel, _ := filepath.Rel(root, e)
		paths = append(paths, rel)
	}
	if len(examples) < 4 {
		t.Fatalf("expected the example configs, found %d", len(examples))
	}
	for _, p := range paths {
		path := filepath.Join(root, p)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		c, err := Load(path)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if len(c.Auth.Modes) == 0 {
			t.Errorf("%s: no auth modes", p)
		}
	}
}

func TestAnnotationScope(t *testing.T) {
	c := Default()
	a := c.Integration.Annotations
	if a.Editable("apps") {
		t.Fatal("disabled feature must not be editable")
	}
	a.Enabled = true
	if !a.Editable("apps") || a.Editable("kube-system") {
		t.Fatal("default exclusions wrong")
	}
	a.AllowNamespaces = []string{"web"}
	if a.Editable("apps") || !a.Editable("web") {
		t.Fatal("allow list not applied")
	}
}
