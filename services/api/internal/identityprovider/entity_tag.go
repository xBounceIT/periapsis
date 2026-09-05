package identityprovider

import (
	"errors"
	"strconv"
)

// EntityTag returns the strong provider validator. Provider version changes
// on every public provider/configuration/endpoint/secret mutation, so the
// quoted version alone is a complete strong validator for this resource.
func EntityTag(version int64) (string, error) {
	if version < 1 || version > maximumResourceVersion {
		return "", errors.New("identity-provider version must be positive")
	}
	return "\"v" + strconv.FormatInt(version, 10) + "\"", nil
}

func parseEntityTag(value string) (int64, error) {
	if len(value) < 4 || value[0] != '"' || value[len(value)-1] != '"' || value[1] != 'v' {
		return 0, ErrInvalidInput
	}
	body := value[2 : len(value)-1]
	if body == "" || body[0] == '0' {
		return 0, ErrInvalidInput
	}
	for _, character := range body {
		if character < '0' || character > '9' {
			return 0, ErrInvalidInput
		}
	}
	version, err := strconv.ParseInt(body, 10, 64)
	if err != nil || version < 1 || version > maximumResourceVersion {
		return 0, ErrInvalidInput
	}
	return version, nil
}
