package app

import (
	"net/netip"
	"testing"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestAllowlistAllowsIPCIDRPathAndUserAgent(t *testing.T) {
	allowlist, err := NewAllowlist(AllowlistConfig{
		IPs:             []string{"192.0.2.10"},
		CIDRs:           []string{"198.51.100.0/24"},
		PathPrefixes:    []string{"/healthz"},
		UserAgentSubstr: []string{"uptime-check"},
	})
	if err != nil {
		t.Fatalf("NewAllowlist() error = %v", err)
	}

	cases := []domain.LogEntry{
		{IP: netip.MustParseAddr("192.0.2.10"), Path: "/"},
		{IP: netip.MustParseAddr("198.51.100.42"), Path: "/"},
		{IP: netip.MustParseAddr("203.0.113.10"), Path: "/healthz/ready"},
		{IP: netip.MustParseAddr("203.0.113.10"), Path: "/", UserAgent: "Uptime-Check/1.0"},
	}
	for _, entry := range cases {
		if !allowlist.Allows(&entry) {
			t.Fatalf("Allows(%+v) = false, want true", entry)
		}
	}
}

func TestAllowlistRejectsNonMatchingEntry(t *testing.T) {
	allowlist, err := NewAllowlist(AllowlistConfig{
		IPs:          []string{"192.0.2.10"},
		CIDRs:        []string{"198.51.100.0/24"},
		PathPrefixes: []string{"/healthz"},
	})
	if err != nil {
		t.Fatalf("NewAllowlist() error = %v", err)
	}

	entry := &domain.LogEntry{
		IP:        netip.MustParseAddr("203.0.113.10"),
		Path:      "/login",
		UserAgent: "Mozilla/5.0",
	}
	if allowlist.Allows(entry) {
		t.Fatal("Allows() = true, want false")
	}
}
