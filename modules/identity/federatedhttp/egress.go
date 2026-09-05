package federatedhttp

import (
	"context"
	"net/netip"
	"slices"
)

var privateNetworkRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

var metadataServiceRanges = []netip.Prefix{
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

var blockedSpecialRanges = []netip.Prefix{
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
	netip.MustParsePrefix("::/96"),
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

func normalizePrivateCIDRs(values []netip.Prefix) ([]netip.Prefix, error) {
	if len(values) > maximumPrivateCIDRs {
		return nil, ErrInvalidOptions
	}
	result := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, prefix := range values {
		if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
			prefix != prefix.Masked() || !isPrivateSubprefix(prefix) {
			return nil, ErrInvalidOptions
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, ErrInvalidOptions
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	slices.SortFunc(result, func(left, right netip.Prefix) int {
		if compared := left.Addr().Compare(right.Addr()); compared != 0 {
			return compared
		}
		return left.Bits() - right.Bits()
	})
	return result, nil
}

func isPrivateSubprefix(candidate netip.Prefix) bool {
	for _, privateRange := range privateNetworkRanges {
		if candidate.Addr().BitLen() == privateRange.Addr().BitLen() &&
			candidate.Bits() >= privateRange.Bits() && privateRange.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func normalizeHTTPSPorts(values []uint16) (map[uint16]struct{}, error) {
	if len(values) == 0 {
		values = []uint16{443}
	}
	if len(values) > maximumAllowedHTTPSPorts {
		return nil, ErrInvalidOptions
	}
	ports := make(map[uint16]struct{}, len(values))
	for _, port := range values {
		if port == 0 {
			return nil, ErrInvalidOptions
		}
		if _, duplicate := ports[port]; duplicate {
			return nil, ErrInvalidOptions
		}
		ports[port] = struct{}{}
	}
	return ports, nil
}

func (client *Client) resolve(ctx context.Context, host string) ([]netip.Addr, Category) {
	if literal, err := netip.ParseAddr(host); err == nil {
		if literal.Zone() != "" || literal.Is4In6() || literal.String() != host ||
			!client.addressAllowed(literal) {
			return nil, CategoryDestinationBlocked
		}
		return []netip.Addr{literal}, CategorySuccess
	}
	addresses, err := client.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		if contextEnded(ctx) {
			return nil, CategoryConnectTimeout
		}
		return nil, CategoryDNSFailed
	}
	if len(addresses) == 0 {
		return nil, CategoryDNSFailed
	}
	if len(addresses) > maximumResolvedAddresses {
		return nil, CategoryDestinationBlocked
	}
	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if address.Zone() != "" || address.Is4In6() || !client.addressAllowed(address) {
			return nil, CategoryDestinationBlocked
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		validated = append(validated, address)
	}
	if len(validated) == 0 {
		return nil, CategoryDNSFailed
	}
	slices.SortFunc(validated, netip.Addr.Compare)
	return validated, CategorySuccess
}

func (client *Client) addressAllowed(address netip.Addr) bool {
	if client == nil || !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return false
	}
	for _, blocked := range metadataServiceRanges {
		if blocked.Contains(address) {
			return false
		}
	}
	if address.IsPrivate() {
		for _, allowed := range client.policy.privateCIDRs {
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
