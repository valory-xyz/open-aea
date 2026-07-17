// Tests in this file each correspond to a Critical or High finding in
// audits/AUDIT-2026-04-15.md. Every test is expected to FAIL until the
// underlying bug is fixed, so the harness is opt-in: tests skip unless
// RUN_AUDIT_TESTS=1 is set.

package dhtnode

import (
	"os"
	"testing"

	"libp2p_node/acn"
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

// TestAuditC2_EmptyPeerPublicKeyAcceptedByPoR verifies that
// IsValidProofOfRepresentation rejects records with an empty
// PeerPublicKey field. See AUDIT-2026-04-15.md C2 (downgraded to High
// after peer review).
//
// Today the function only checks `record.PeerPublicKey ==
// representativePeerPubKey`. When the caller in dht/common/handlers.go
// silently swallows the error from FetchAIPublicKeyFromPubKey, the
// representative pubkey is the empty string and any record with
// PeerPublicKey == "" passes this check trivially.
//
// The fix is to reject empty-string PeerPublicKey unconditionally, so
// the empty-string-equality bypass is unreachable even if a future
// caller supplies an empty representative key.
func TestAuditC2_EmptyPeerPublicKeyAcceptedByPoR(t *testing.T) {
	skipUnlessAuditRun(t)
	record := &acn.AgentRecord{
		Address:       "fetch1someaddress",
		PublicKey:     "0260b9be4a90f8d68b1cd6f73fbc83bbe6db48dd1d10cf606e23f9e98be4eaf04a",
		PeerPublicKey: "", // attacker-controlled empty value
		Signature:     "deadbeef",
		LedgerId:      "fetchai",
	}

	// Recover defensively — downstream checks may panic on malformed
	// inputs (which would itself be a separate audit finding).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AUDIT C2: IsValidProofOfRepresentation panicked on empty PeerPublicKey input: %v", r)
		}
	}()

	status, err := IsValidProofOfRepresentation(record, record.Address, "")

	// The empty-string equality check should reject this record up-front
	// with a clear ERROR_WRONG_PUBLIC_KEY status. Reaching any later
	// check (or success) means the empty-string-bypass class of bug
	// remains reachable from any caller that supplies an empty
	// representative key — which is exactly what the buggy
	// dht/common/handlers.go path does today after `ignore(err)`.
	if status == nil || status.Code != acn.ERROR_WRONG_PUBLIC_KEY {
		t.Fatalf("AUDIT C2: empty PeerPublicKey did NOT trigger the dedicated PoR rejection; got status=%v err=%v. The empty-string equality bypass remains reachable.", status, err)
	}
}
