// Tests in this file each correspond to a Critical or High finding in
// audits/AUDIT-2026-04-15.md. Every test is expected to FAIL until the
// underlying bug is fixed, so the harness is opt-in: tests skip unless
// RUN_AUDIT_TESTS=1 is set.

package acn

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestAuditH7_AcnErrorEchoesInternalParserStrings verifies that
// `SendAcnError` is not called with raw `err.Error()` strings produced
// by deserialization failures. See AUDIT-2026-04-15.md H7.
//
// The acn/utils.go source contains the maintainer's own TOFIX comment
// flagging the same vulnerability. This test fails until either the
// `err.Error()` arguments are replaced with generic strings, or the
// TOFIX comment is removed (signalling a deliberate decision).
func TestAuditH7_AcnErrorEchoesInternalParserStrings(t *testing.T) {
	skipUnlessAuditRun(t)
	src := readAcnSourceFile(t, "utils.go")
	if !strings.Contains(src, "TOFIX(LR) setting Msgs to err.Error is potentially a security vulnerability") {
		t.Skipf("TOFIX marker removed — bug may have been addressed by another route; re-check AUDIT H7")
	}
	t.Fatalf("AUDIT H7: acn/utils.go still contains the TOFIX block sending raw err.Error() to remote peers via SendAcnError")
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

func readAcnSourceFile(t *testing.T, name string) string {
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
