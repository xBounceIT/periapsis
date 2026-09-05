package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedPoolConfigNeverUsesInheritedPassfile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pgpass")
	if err := os.WriteFile(file, []byte("*:*:*:*:synthetic-passfile-must-not-be-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGPASSFILE", file)
	t.Setenv("PGPASSWORD", "")
	parsed, err := parsePinnedPoolConfig(configTestURL)
	if err != nil || parsed.ConnConfig.Password != "" {
		t.Fatal("inherited password file affected the pinned connection")
	}
}
