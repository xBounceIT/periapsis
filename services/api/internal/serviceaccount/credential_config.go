package serviceaccount

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const maximumCredentialKeyringDocumentBytes = 16 * 1024

type credentialKeyringDocument struct {
	ActiveVersion int16                    `json:"activeVersion"`
	Keys          []credentialKeyringEntry `json:"keys"`
}

type credentialKeyringEntry struct {
	Version int16                `json:"version"`
	Key     *credentialSourceKey `json:"key"`
}

type credentialSourceKey [credentialSourceKeyBytes]byte

// ParseCredentialKeyring parses the file-mounted JSON keyring. Keys are an
// array so duplicate versions can be rejected instead of being overwritten by
// JSON object semantics. Error messages never include key material.
func ParseCredentialKeyring(value []byte) (CredentialKeyring, error) {
	if len(value) == 0 || len(value) > maximumCredentialKeyringDocumentBytes {
		return CredentialKeyring{}, errors.New("credential keyring document is missing or too large")
	}
	if err := rejectDuplicateCredentialKeyringMembers(value); err != nil {
		return CredentialKeyring{}, errors.New("credential keyring document is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var document credentialKeyringDocument
	defer clearCredentialKeyringDocument(&document)
	if err := decoder.Decode(&document); err != nil {
		return CredentialKeyring{}, errors.New("credential keyring document is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CredentialKeyring{}, errors.New("credential keyring document contains trailing data")
	}
	if len(document.Keys) == 0 || len(document.Keys) > 16 {
		return CredentialKeyring{}, errors.New("credential keyring must contain between 1 and 16 keys")
	}
	sourceKeys := make(map[int16][]byte, len(document.Keys))
	for _, entry := range document.Keys {
		if _, exists := sourceKeys[entry.Version]; exists {
			return CredentialKeyring{}, errors.New("credential keyring contains a duplicate version")
		}
		if entry.Key == nil {
			return CredentialKeyring{}, errors.New("credential keyring keys must be canonical padded Base64 for exactly 32 bytes")
		}
		sourceKeys[entry.Version] = entry.Key[:]
	}
	return NewCredentialKeyring(document.ActiveVersion, sourceKeys)
}

func (k *credentialSourceKey) UnmarshalJSON(value []byte) error {
	clear(k[:])
	encodedBytes := base64.StdEncoding.EncodedLen(credentialSourceKeyBytes)
	if len(value) != encodedBytes+2 || value[0] != '"' || value[len(value)-1] != '"' {
		return errors.New("credential source key is not canonical Base64")
	}
	decoded, err := base64.StdEncoding.Strict().Decode(k[:], value[1:len(value)-1])
	if err != nil || decoded != credentialSourceKeyBytes {
		clear(k[:])
		return errors.New("credential source key is not canonical Base64")
	}
	return nil
}

func clearCredentialKeyringDocument(document *credentialKeyringDocument) {
	for index := range document.Keys {
		if document.Keys[index].Key != nil {
			clear(document.Keys[index].Key[:])
		}
	}
}

func rejectDuplicateCredentialKeyringMembers(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	var document json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	defer clear(document)
	return rejectDuplicateCredentialKeyringValue(document)
}

func rejectDuplicateCredentialKeyringValue(value json.RawMessage) error {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := opening.(json.Delim)
	if !ok {
		return errors.New("JSON compound value has no delimiter")
	}
	switch delimiter {
	case '{':
		members := make([]string, 0)
		for decoder.More() {
			nameToken, tokenErr := decoder.Token()
			if tokenErr != nil {
				return tokenErr
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object member name is invalid")
			}
			for _, existing := range members {
				// encoding/json matches struct fields with strings.EqualFold
				// semantics. Apply the same Unicode folding here so two names
				// cannot target one field and acquire order-dependent meaning.
				if strings.EqualFold(existing, name) {
					return errors.New("JSON object member is duplicated")
				}
			}
			members = append(members, name)
			var child json.RawMessage
			if err := decoder.Decode(&child); err != nil {
				clear(child)
				return err
			}
			childErr := rejectDuplicateCredentialKeyringValue(child)
			clear(child)
			if childErr != nil {
				return childErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			var child json.RawMessage
			if err := decoder.Decode(&child); err != nil {
				clear(child)
				return err
			}
			childErr := rejectDuplicateCredentialKeyringValue(child)
			clear(child)
			if childErr != nil {
				return childErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
