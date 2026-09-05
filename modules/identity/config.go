package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const maximumKeyringDocumentBytes = 16 * 1024

type keyringDocument struct {
	ActiveVersion int16          `json:"activeVersion"`
	Keys          []keyringEntry `json:"keys"`
}

type keyringEntry struct {
	Version int16      `json:"version"`
	Key     *sourceKey `json:"key"`
}

type sourceKey [sourceKeyBytes]byte

// ParseKeyringDocument parses a file-mounted JSON identity keyring. It always
// clears source before returning, including on failure. Keys are represented
// as an array so duplicate versions cannot be silently overwritten.
func ParseKeyringDocument(source []byte) (Keyring, error) {
	defer clear(source)
	if len(source) == 0 || len(source) > maximumKeyringDocumentBytes {
		return Keyring{}, ErrInvalidKeyring
	}
	if err := rejectDuplicateMembers(source); err != nil {
		return Keyring{}, ErrInvalidKeyring
	}

	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	var document keyringDocument
	defer clearKeyringDocument(&document)
	if err := decoder.Decode(&document); err != nil {
		return Keyring{}, ErrInvalidKeyring
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Keyring{}, ErrInvalidKeyring
	}
	if document.ActiveVersion < 1 || len(document.Keys) < 1 || len(document.Keys) > maximumKeyCount {
		return Keyring{}, ErrInvalidKeyring
	}

	sourceKeys := make(map[int16][]byte, len(document.Keys))
	defer clearSourceKeys(sourceKeys)
	for _, entry := range document.Keys {
		if entry.Version < 1 || entry.Key == nil {
			return Keyring{}, ErrInvalidKeyring
		}
		if _, exists := sourceKeys[entry.Version]; exists {
			return Keyring{}, ErrInvalidKeyring
		}
		sourceKeys[entry.Version] = entry.Key[:]
	}
	return NewKeyring(document.ActiveVersion, sourceKeys)
}

func (key *sourceKey) UnmarshalJSON(value []byte) error {
	clear(key[:])
	encodedBytes := base64.StdEncoding.EncodedLen(sourceKeyBytes)
	if len(value) != encodedBytes+2 || value[0] != '"' || value[len(value)-1] != '"' {
		return ErrInvalidKeyring
	}
	encoded := value[1 : len(value)-1]
	// A 33-byte value has the same 44-character encoded length as a
	// 32-byte value. Decode into the maximum-sized temporary buffer so an
	// attacker-controlled document can never overrun the fixed destination.
	var decoded [sourceKeyBytes + 1]byte
	defer clear(decoded[:])
	decodedBytes, err := base64.StdEncoding.Strict().Decode(decoded[:], encoded)
	if err != nil || decodedBytes != sourceKeyBytes {
		clear(key[:])
		return ErrInvalidKeyring
	}
	copy(key[:], decoded[:sourceKeyBytes])
	return nil
}

func clearKeyringDocument(document *keyringDocument) {
	for index := range document.Keys {
		if document.Keys[index].Key != nil {
			clear(document.Keys[index].Key[:])
		}
	}
}

func clearSourceKeys(keys map[int16][]byte) {
	for version, key := range keys {
		clear(key)
		keys[version] = nil
	}
}

func rejectDuplicateMembers(source []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(source))
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	defer clear(value)
	return rejectDuplicateValue(value)
}

func rejectDuplicateValue(value json.RawMessage) error {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' && trimmed[0] != '[' {
		return nil
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := opening.(json.Delim)
	if !ok {
		return errors.New("invalid JSON compound value")
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
				return errors.New("invalid JSON object member")
			}
			for _, existing := range members {
				// encoding/json matches struct fields using Unicode case-folding.
				// Reject the same equivalence class before field selection can
				// give the document order-dependent meaning.
				if strings.EqualFold(existing, name) {
					return errors.New("duplicate JSON object member")
				}
			}
			members = append(members, name)
			var child json.RawMessage
			if err := decoder.Decode(&child); err != nil {
				clear(child)
				return err
			}
			childErr := rejectDuplicateValue(child)
			clear(child)
			if childErr != nil {
				return childErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("unclosed JSON object")
		}
	case '[':
		for decoder.More() {
			var child json.RawMessage
			if err := decoder.Decode(&child); err != nil {
				clear(child)
				return err
			}
			childErr := rejectDuplicateValue(child)
			clear(child)
			if childErr != nil {
				return childErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("unclosed JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
