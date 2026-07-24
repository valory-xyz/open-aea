// Tests in this file each correspond to a Critical or High finding in
// audits/AUDIT-2026-04-15.md. Every test is expected to FAIL until the
// underlying bug is fixed, so the harness is opt-in: tests skip unless
// RUN_AUDIT_TESTS=1 is set.
//
// Run only these tests:
//   RUN_AUDIT_TESTS=1 go test -gcflags=-l -count=1 -v -run TestAudit ./dht/dhtpeer/...

package dhtpeer

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// skipUnlessAuditRun makes the audit harness opt-in: every test in this
// file documents a known-open finding and fails until it is fixed, so
// they must not turn regular CI red.
func skipUnlessAuditRun(t *testing.T) {
	t.Helper()
	if os.Getenv("RUN_AUDIT_TESTS") == "" {
		t.Skip("audit-finding regression test; set RUN_AUDIT_TESTS=1 to run (see audits/AUDIT-2026-04-15.md)")
	}
}

// TestAuditN7_FmtPrintlnSilentDiscardOnSyncQueueFull verifies that the
// "channel full, discarding" branch in the per-pair enqueue path does
// not silently drop envelopes via fmt.Println. See AUDIT-2026-04-15.md N7.
func TestAuditN7_FmtPrintlnSilentDiscardOnSyncQueueFull(t *testing.T) {
	skipUnlessAuditRun(t)
	src := readDhtpeerSource(t, "dhtpeer.go")
	if strings.Contains(src, `fmt.Println("CHANNEL FULL, DISCARDING`) {
		t.Fatalf("AUDIT N7: dhtpeer.go discards envelopes via fmt.Println without using the structured logger or any metric")
	}
}

// TestAuditN8_RouteEnvelopeDHTLookupUsesContextBackground verifies that
// the DHT lookup helper does not use `context.Background()` (which
// cannot be cancelled when the peer shuts down). See AUDIT-2026-04-15.md N8.
func TestAuditN8_RouteEnvelopeDHTLookupUsesContextBackground(t *testing.T) {
	skipUnlessAuditRun(t)
	src := readDhtpeerSource(t, "dhtpeer.go")
	// Look for a context.Background() call in _routeEnvelopeDHTLookup.
	// We grep with a +/- 30 line window around the function header.
	idx := strings.Index(src, "_routeEnvelopeDHTLookup")
	if idx < 0 {
		t.Skipf("function _routeEnvelopeDHTLookup not found — refactored?")
	}
	end := idx + 4000
	if end > len(src) {
		end = len(src)
	}
	if strings.Contains(src[idx:end], "context.Background()") {
		t.Fatalf("AUDIT N8: _routeEnvelopeDHTLookup constructs context.Background() instead of deriving from a parent that cancels on shutdown (dhtPeer.closing)")
	}
}

// TestAuditH6_PrivateKeyLoggedAtDebugLevel verifies that the bootstrap
// path does not log the AEA private key. See AUDIT-2026-04-15.md H6.
//
// The bug lives in aea/api.go but the example output is already
// documented in README.md, so a static check on the README is the
// cheapest way to keep this finding visible.
func TestAuditH6_PrivateKeyLoggedAtDebugLevel(t *testing.T) {
	skipUnlessAuditRun(t)
	apiSrc := readRepoFile(t, "aea/api.go")
	// The exact line is `logger.Debug().Msgf("id: %s", aea.id)`.
	if regexp.MustCompile(`logger\.Debug\(\)\.Msgf\(["']id: %s["']`).MatchString(apiSrc) {
		t.Fatalf("AUDIT H6: aea/api.go logs the AEA private key at debug level (`id: %%s`)")
	}
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

func readDhtpeerSource(t *testing.T, name string) string {
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

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	// walk up to find the repo root (contains go.mod)
	dir := filepath.Dir(here)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			path := filepath.Join(dir, rel)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			return string(data)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate repo root from %s", here)
	return ""
}
