package app

import (
	"net/netip"
	"strings"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type AllowlistConfig struct {
	IPs             []string
	CIDRs           []string
	PathPrefixes    []string
	UserAgentSubstr []string
}

type Allowlist struct {
	ips             map[netip.Addr]struct{}
	prefixes        []netip.Prefix
	pathPrefixes    []string
	userAgentSubstr []string
}

func NewAllowlist(config AllowlistConfig) (*Allowlist, error) {
	allowlist := &Allowlist{
		ips:             make(map[netip.Addr]struct{}, len(config.IPs)),
		pathPrefixes:    normalizeList(config.PathPrefixes, false),
		userAgentSubstr: normalizeList(config.UserAgentSubstr, true),
	}

	for _, raw := range config.IPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, err
		}
		allowlist.ips[ip] = struct{}{}
	}

	for _, raw := range config.CIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, err
		}
		allowlist.prefixes = append(allowlist.prefixes, prefix.Masked())
	}

	return allowlist, nil
}

func (a *Allowlist) Allows(entry *domain.LogEntry) bool {
	if a == nil || entry == nil {
		return false
	}

	if entry.IP.IsValid() {
		if _, ok := a.ips[entry.IP]; ok {
			return true
		}
		for _, prefix := range a.prefixes {
			if prefix.Contains(entry.IP) {
				return true
			}
		}
	}

	for _, prefix := range a.pathPrefixes {
		if strings.HasPrefix(entry.Path, prefix) {
			return true
		}
	}

	userAgent := strings.ToLower(entry.UserAgent)
	for _, needle := range a.userAgentSubstr {
		if strings.Contains(userAgent, needle) {
			return true
		}
	}

	return false
}

func normalizeList(values []string, lower bool) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if lower {
			value = strings.ToLower(value)
		}
		result = append(result, value)
	}
	return result
}
