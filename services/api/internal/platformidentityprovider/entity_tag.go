package platformidentityprovider

import (
	"errors"
	"strconv"
)

// EntityTag returns the canonical strong validator for the provider's
// versioned public representation.
func EntityTag(version int64) (string, error) {
	if !validResourceVersion(version) {
		return "", errors.New("platform identity provider version is invalid")
	}
	return "\"v" + strconv.FormatInt(version, 10) + "\"", nil
}

func parseEntityTag(value string) (int64, error) {
	if len(value) < 4 || value[0] != '"' || value[len(value)-1] != '"' || value[1] != 'v' {
		return 0, errors.New("platform identity provider ETag is invalid")
	}
	body := value[2 : len(value)-1]
	if body == "" || body[0] == '0' {
		return 0, errors.New("platform identity provider ETag is invalid")
	}
	for _, character := range body {
		if character < '0' || character > '9' {
			return 0, errors.New("platform identity provider ETag is invalid")
		}
	}
	version, err := strconv.ParseInt(body, 10, 64)
	if err != nil || !validResourceVersion(version) {
		return 0, errors.New("platform identity provider ETag is invalid")
	}
	return version, nil
}
