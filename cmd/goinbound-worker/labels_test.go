package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoReservedMetricLabels: Prometheus attaches its own "instance" and "job"
// labels at scrape time, and renames a clashing label of ours to
// "exported_instance". Every panel grouping by it then groups by the scrape
// target instead -- silently, with the right-looking legend. It happened to
// the EDU writer label.
func TestNoReservedMetricLabels(t *testing.T) {
	labelList := regexp.MustCompile(`\}, \[\]string\{([^}]*)\}\)`)
	reserved := regexp.MustCompile(`"(instance|job)"`)
	found := 0
	err := filepath.WalkDir("../../internal", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range labelList.FindAllSubmatch(b, -1) {
			found++
			if reserved.Match(m[1]) {
				t.Errorf("%s: metric label list {%s} uses a label Prometheus reserves", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("found no metric label lists; the test is not looking where they are")
	}
}
