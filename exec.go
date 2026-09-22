// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// findGittufBinary locates the gittuf executable.
func findGittufBinary() string {
	if p := os.Getenv("GITTUF_PATH"); p != "" {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	candidates := []string{
		`C:\Users\explo\Desktop\gittuf\gittuf.exe`,
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "Desktop", "gittuf", "gittuf.exe"),
			filepath.Join(home, "Desktop", "gittuf", "gittuf"),
			filepath.Join(home, "go", "bin", "gittuf.exe"),
			filepath.Join(home, "go", "bin", "gittuf"),
		)
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	cwd, err := os.Getwd()
	if err == nil {
		dir := cwd
		for {
			for _, name := range []string{"gittuf.exe", "gittuf"} {
				candidate := filepath.Join(dir, name)
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					return candidate
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if path, err := exec.LookPath("gittuf"); err == nil {
		return path
	}
	return "gittuf"
}

// execCmd is the low-level command runner used by runGit and runCmd.
// It returns trimmed stdout on success, or a wrapped error with stderr on failure.
func execCmd(dir string, name string, args ...string) (string, error) {
	if name == "gittuf" {
		name = findGittufBinary()
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		return out, fmt.Errorf("%s %s failed: %w\nstderr: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// runCmd is an alias for execCmd, used when the command is not git.
func runCmd(dir string, name string, args ...string) (string, error) {
	return execCmd(dir, name, args...)
}
