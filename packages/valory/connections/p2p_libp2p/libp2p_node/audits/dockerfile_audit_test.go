// Tests in this file each correspond to a Critical or High finding in
// AUDIT-2026-04-15.md. Every test is expected to FAIL until the
// underlying bug is fixed, so the harness is opt-in: tests skip unless
// RUN_AUDIT_TESTS=1 is set.

package audits

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestAuditH11a_DockerfileRunsAsRoot verifies that the container does
// not run as root. See AUDIT-2026-04-15.md H11.
func TestAuditH11a_DockerfileRunsAsRoot(t *testing.T) {
	skipUnlessAuditRun(t)
	df := readDockerfile(t)
	if !regexp.MustCompile(`(?m)^USER\s+root\s*$`).MatchString(df) {
		// No `USER root` line — fine.
		return
	}
	// Look for a subsequent USER directive switching to a non-root user
	// before the ENTRYPOINT.
	if hasNonRootUserBeforeEntrypoint(df) {
		return
	}
	t.Fatalf("AUDIT H11: Dockerfile sets `USER root` and never switches to a non-root user before ENTRYPOINT")
}

// TestAuditH11b_DockerfileGoToolchainNotChecksumVerified verifies that
// the Go toolchain download is checksum-verified. See AUDIT H11.
func TestAuditH11b_DockerfileGoToolchainNotChecksumVerified(t *testing.T) {
	skipUnlessAuditRun(t)
	df := readDockerfile(t)
	hasWgetGo := regexp.MustCompile(`wget\s+https://dl\.google\.com/go/`).MatchString(df)
	if !hasWgetGo {
		return // no download to verify
	}
	hasChecksum := strings.Contains(df, "sha256sum") || strings.Contains(df, "shasum") || strings.Contains(df, "sha256")
	if !hasChecksum {
		t.Fatalf("AUDIT H11: Dockerfile downloads the Go toolchain via wget without any sha256sum / signature verification")
	}
}

// TestAuditH11c_DockerfilePipUnpinned verifies that pip installs are
// version-pinned. See AUDIT H11 / L8.
func TestAuditH11c_DockerfilePipUnpinned(t *testing.T) {
	skipUnlessAuditRun(t)
	df := readDockerfile(t)
	pipLine := regexp.MustCompile(`(?m)^.*pip\s+install\s+(.+)$`).FindStringSubmatch(df)
	if pipLine == nil {
		return
	}
	pkgs := strings.Fields(pipLine[1])
	for _, p := range pkgs {
		if strings.HasPrefix(p, "-") {
			continue
		}
		if !strings.ContainsAny(p, "=<>") {
			t.Fatalf("AUDIT H11: pip install line has unpinned package %q (full match: %q)", p, pipLine[0])
		}
	}
}

// ---------------------------------------------------------------------

// skipUnlessAuditRun makes the audit harness opt-in: every test in this
// file documents a known-open finding and fails until it is fixed, so
// they must not turn regular CI red.
func skipUnlessAuditRun(t *testing.T) {
	t.Helper()
	if os.Getenv("RUN_AUDIT_TESTS") == "" {
		t.Skip("audit-finding regression test; set RUN_AUDIT_TESTS=1 to run (see audits/AUDIT-2026-04-15.md)")
	}
}

func readDockerfile(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	dir := filepath.Dir(here)
	for i := 0; i < 4; i++ {
		path := filepath.Join(dir, "Dockerfile")
		if data, err := os.ReadFile(path); err == nil {
			return string(data)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate Dockerfile")
	return ""
}

func hasNonRootUserBeforeEntrypoint(df string) bool {
	lines := strings.Split(df, "\n")
	sawNonRootUser := false
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "USER ") {
			user := strings.TrimSpace(strings.TrimPrefix(trimmed, "USER"))
			if user != "" && user != "root" && user != "0" {
				sawNonRootUser = true
			} else {
				sawNonRootUser = false
			}
		}
		if strings.HasPrefix(trimmed, "ENTRYPOINT") {
			return sawNonRootUser
		}
	}
	return sawNonRootUser
}
