// Tests in this file each correspond to a Critical or High finding in
// audits/AUDIT-2026-04-15.md. Every test is expected to FAIL until the
// underlying bug is fixed, so the harness is opt-in: tests skip unless
// RUN_AUDIT_TESTS=1 is set. No source code changes accompany this file —
// it is purely a regression harness for the audit findings.
//
// Run only these tests:
//   RUN_AUDIT_TESTS=1 go test -gcflags=-l -count=1 -v -run TestAudit ./aea/...

package aea

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
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

// TestAuditC1_PipeReadAcceptsHugeSizePrefix verifies that
// TCPSocketChannel.Read rejects (or at minimum bounds) a 4-byte length
// prefix that claims a 4 GiB payload. See AUDIT-2026-04-15.md C1.
//
// Currently the call does `make([]byte, size)` with no upper bound,
// which either OOMs the process or, on some allocators, succeeds and
// then blocks forever in conn.Read.
func TestAuditC1_PipeReadAcceptsHugeSizePrefix(t *testing.T) {
	skipUnlessAuditRun(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Announce a 100 MiB payload — well past any sensible AEA
		// envelope size (the rest of the codebase caps at ~3 MiB for the
		// delegate connection) but small enough not to risk allocator
		// behaviour skewing the test on resource-constrained CI runners.
		// The SUT should reject this without attempting to allocate.
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, 100*1024*1024)
		_, _ = conn.Write(hdr)
		// Hold the connection open so the SUT cannot exit on EOF.
		time.Sleep(2 * time.Second)
	}()

	sock := &TCPSocketChannel{port: port}
	if err := sock.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sock.Close()

	type readResult struct {
		buf   []byte
		err   error
		panic any
	}
	done := make(chan readResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- readResult{panic: r}
			}
		}()
		buf, err := sock.Read()
		done <- readResult{buf: buf, err: err}
	}()

	select {
	case res := <-done:
		switch {
		case res.panic != nil:
			t.Fatalf("AUDIT C1: pipe.Read panicked attempting to allocate the announced payload size: %v", res.panic)
		case res.err == nil:
			t.Fatalf("AUDIT C1: pipe.Read accepted a 100 MiB length prefix without error (returned %d bytes)", len(res.buf))
		case !isSizeCapError(res.err):
			t.Fatalf("AUDIT C1: pipe.Read returned %q for a 100 MiB length prefix; expected an explicit size-cap rejection", res.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("AUDIT C1: pipe.Read blocked > 3s on a 100 MiB length prefix instead of rejecting it")
	}
}

// isSizeCapError returns true if err looks like an explicit
// envelope-size cap rejection (rather than an I/O error or EOF).
// The exact error string is left to whoever implements the cap; this
// helper accepts any of the obvious phrasings.
func isSizeCapError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, needle := range []string{"size exceeds", "too large", "exceeds maximum", "envelope size"} {
		if containsFold(s, needle) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a := s[i+j]
			b := sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
