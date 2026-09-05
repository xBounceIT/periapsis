package platformidentityaccount

import (
	"errors"
	"strconv"
	"strings"
)

// EntityTag returns the canonical strong validator for the joined safe account
// and user representation.
func EntityTag(resourceVersion, userVersion int64) (string, error) {
	if !validResourceVersion(resourceVersion) || !validResourceVersion(userVersion) {
		return "", errors.New("platform identity account version is invalid")
	}
	return "\"v" + strconv.FormatInt(resourceVersion, 10) +
		"-u" + strconv.FormatInt(userVersion, 10) + "\"", nil
}

// ParseEntityTag accepts only one canonical strong validator. Weak, wildcard,
// padded, folded, list, and overflowing forms fail closed.
func ParseEntityTag(value string) (int64, int64, error) {
	if len(value) < 7 || value[0] != '"' || value[len(value)-1] != '"' || value[1] != 'v' {
		return 0, 0, errors.New("platform identity account ETag is invalid")
	}
	body := value[2 : len(value)-1]
	resourceBody, userBody, found := strings.Cut(body, "-u")
	if !found || resourceBody == "" || userBody == "" {
		return 0, 0, errors.New("platform identity account ETag is invalid")
	}
	if resourceBody[0] == '0' || userBody[0] == '0' {
		return 0, 0, errors.New("platform identity account ETag is invalid")
	}
	for _, character := range resourceBody + userBody {
		if character < '0' || character > '9' {
			return 0, 0, errors.New("platform identity account ETag is invalid")
		}
	}
	resourceVersion, resourceErr := strconv.ParseInt(resourceBody, 10, 64)
	userVersion, userErr := strconv.ParseInt(userBody, 10, 64)
	if resourceErr != nil || userErr != nil || !validResourceVersion(resourceVersion) ||
		!validResourceVersion(userVersion) {
		return 0, 0, errors.New("platform identity account ETag is invalid")
	}
	canonical, err := EntityTag(resourceVersion, userVersion)
	if err != nil || canonical != value {
		return 0, 0, errors.New("platform identity account ETag is invalid")
	}
	return resourceVersion, userVersion, nil
}
