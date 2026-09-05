package ldapclient

import "net/netip"

var privateNetworkRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

var metadataServiceRanges = []netip.Prefix{
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

var blockedSpecialRanges = []netip.Prefix{
	// IPv4 special-purpose, shared, documentation, benchmark, multicast,
	// future-use, and metadata-capable address space.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv6 translation, discard, IETF-special, documentation, deprecated,
	// site-local, segment-routing, link-local, and multicast ranges.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func normalizePrivateEgressCIDRs(values []netip.Prefix) ([]netip.Prefix, error) {
	if len(values) > maximumPrivateCIDRs {
		return nil, ErrInvalidOptions
	}
	normalized := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, prefix := range values {
		if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix != prefix.Masked() ||
			!isPrivateNetworkPrefix(prefix) {
			return nil, ErrInvalidOptions
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, ErrInvalidOptions
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	return normalized, nil
}

func isPrivateNetworkPrefix(candidate netip.Prefix) bool {
	for _, privateRange := range privateNetworkRanges {
		if candidate.Addr().BitLen() == privateRange.Addr().BitLen() &&
			candidate.Bits() >= privateRange.Bits() && privateRange.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func (c *Client) addressAllowed(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	for _, blocked := range metadataServiceRanges {
		if blocked.Contains(address) {
			return false
		}
	}
	if address.IsPrivate() {
		for _, allowed := range c.privateEgressCIDRs {
			if allowed.Contains(address) {
				return true
			}
		}
		return false
	}
	if !address.IsGlobalUnicast() {
		return false
	}
	for _, blocked := range blockedSpecialRanges {
		if blocked.Contains(address) {
			return false
		}
	}
	return true
}
