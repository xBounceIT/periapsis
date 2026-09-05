// Package origin canonicalizes the host component used by browser-origin checks.
package origin

import (
	"errors"
	"net/netip"
	"strings"
)

// CanonicalHostname returns the browser-equivalent ASCII hostname or IP literal.
func CanonicalHostname(value string) (string, error) {
	hostname := strings.ToLower(value)
	if hostname == "" || strings.HasSuffix(hostname, ".") || strings.Contains(hostname, "%") || !isASCII(hostname) {
		return "", errors.New("origin host must be an unambiguous ASCII hostname or IP address")
	}
	if address, err := netip.ParseAddr(hostname); err == nil {
		return address.String(), nil
	}

	labels := strings.Split(hostname, ".")
	if len(hostname) > 253 || looksLikeLegacyIPv4(labels[len(labels)-1]) {
		return "", errors.New("origin host is not canonical")
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || !isAlphaNumeric(label[0]) || !isAlphaNumeric(label[len(label)-1]) {
			return "", errors.New("origin host contains an invalid DNS label")
		}
		for index := 1; index < len(label)-1; index++ {
			if !isAlphaNumeric(label[index]) && label[index] != '-' {
				return "", errors.New("origin host contains an invalid DNS label")
			}
		}
	}
	return hostname, nil
}

func looksLikeLegacyIPv4(lastLabel string) bool {
	if lastLabel == "" {
		return false
	}
	for _, character := range lastLabel {
		if character < '0' || character > '9' {
			return strings.HasPrefix(lastLabel, "0x") && len(lastLabel) > 2 && isHex(lastLabel[2:])
		}
	}
	return true
}

func isHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			lower := character | 0x20
			if lower < 'a' || lower > 'f' {
				return false
			}
		}
	}
	return true
}

func isAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > 0x7f || character < 0x21 {
			return false
		}
	}
	return true
}
