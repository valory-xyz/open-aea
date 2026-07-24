// Tests in this file each correspond to a Critical or High finding in
// audits/AUDIT-2026-04-15.md. Every test is expected to FAIL until the
// underlying bug is fixed, so the harness is opt-in: tests skip unless
// RUN_AUDIT_TESTS=1 is set.

package monitoring

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAuditH10_PrometheusBindsToAllInterfacesByDefault verifies that
// the Prometheus monitoring HTTP server does NOT bind to all
// interfaces by default. See AUDIT-2026-04-15.md H10.
//
// Today the bind address is `:port`, which Go interprets as
// `0.0.0.0:port` on Linux — exposing metrics publicly without auth.
// A safer default is `127.0.0.1:port`; operators that want public
// exposure can opt in.
func TestAuditH10_PrometheusBindsToAllInterfacesByDefault(t *testing.T) {
	skipUnlessAuditRun(t)
	src := readMonitoringSourceFile(t, "prometheus.go")
	if !strings.Contains(src, `httpServer = http.Server{Addr: ":"`) {
		t.Skipf("expected bind pattern not found — bug may have been fixed in another way; re-check AUDIT-2026-04-15.md H10")
	}
	t.Fatalf("AUDIT H10: prometheus.go binds to `:port` (0.0.0.0). Default should be `127.0.0.1:port`.")
}

// skipUnlessAuditRun makes the audit harness opt-in: every test in this
// file documents a known-open finding and fails until it is fixed, so
// they must not turn regular CI red.
func skipUnlessAuditRun(t *testing.T) {
	t.Helper()
	if os.Getenv("RUN_AUDIT_TESTS") == "" {
		t.Skip("audit-finding regression test; set RUN_AUDIT_TESTS=1 to run (see audits/AUDIT-2026-04-15.md)")
	}
}

// readMonitoringSourceFile loads a sibling .go source for static-pattern
// tests that assert the absence of buggy code shapes.
func readMonitoringSourceFile(t *testing.T, name string) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(here), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
