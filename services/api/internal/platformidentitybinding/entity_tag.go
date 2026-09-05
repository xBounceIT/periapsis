package platformidentitybinding

import (
	"errors"
	"strconv"
	"strings"
)

// EntityTag returns the canonical strong validator for the complete binding
// representation. The tenant version is part of the validator because the
// embedded safe tenant summary is read live rather than copied into the
// binding row.
func EntityTag(bindingVersion, tenantVersion int64) (string, error) {
	if !validResourceVersion(bindingVersion) || !validResourceVersion(tenantVersion) {
		return "", errors.New("platform identity binding version is invalid")
	}
	return "\"v" + strconv.FormatInt(bindingVersion, 10) + "-t" +
		strconv.FormatInt(tenantVersion, 10) + "\"", nil
}

// ParseEntityTag accepts only the canonical, single strong validator emitted
// by EntityTag. Weak, wildcard, folded, padded, and overflowing forms fail
// closed.
func ParseEntityTag(value string) (int64, int64, error) {
	if len(value) < len("\"v1-t1\"") || value[0] != '"' ||
		value[len(value)-1] != '"' || value[1] != 'v' {
		return 0, 0, errors.New("platform identity binding ETag is invalid")
	}
	body := value[2 : len(value)-1]
	separator := strings.Index(body, "-t")
	if separator < 1 || separator != strings.LastIndex(body, "-t") ||
		separator+2 >= len(body) {
		return 0, 0, errors.New("platform identity binding ETag is invalid")
	}
	bindingVersion, err := parseEntityTagVersion(body[:separator])
	if err != nil {
		return 0, 0, err
	}
	tenantVersion, err := parseEntityTagVersion(body[separator+2:])
	if err != nil {
		return 0, 0, err
	}
	canonical, err := EntityTag(bindingVersion, tenantVersion)
	if err != nil || canonical != value {
		return 0, 0, errors.New("platform identity binding ETag is invalid")
	}
	return bindingVersion, tenantVersion, nil
}

func parseEntityTagVersion(value string) (int64, error) {
	if value == "" || value[0] == '0' {
		return 0, errors.New("platform identity binding ETag is invalid")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("platform identity binding ETag is invalid")
		}
	}
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || !validResourceVersion(version) {
		return 0, errors.New("platform identity binding ETag is invalid")
	}
	return version, nil
}
