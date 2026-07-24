// Package audits hosts cross-cutting audit-finding regression tests
// (Dockerfile and other repo-level patterns) that have no natural home
// in any of the existing Go packages. The package itself ships nothing
// at runtime — see *_test.go for the actual checks and
// AUDIT-2026-04-15.md for the underlying findings.
package audits
