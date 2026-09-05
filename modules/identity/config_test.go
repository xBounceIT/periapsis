package identity

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParseKeyringDocumentClearsSourceAndBuildsKeyring(t *testing.T) {
	t.Parallel()

	first := encodedRoot(0xA1)
	second := encodedRoot(0xA2)
	source := []byte(fmt.Sprintf(
		`{"activeVersion":2,"keys":[{"version":1,"key":%q},{"version":2,"key":%q}]}`,
		first,
		second,
	))
	keyring, err := ParseKeyringDocument(source)
	if err != nil {
		t.Fatalf("ParseKeyringDocument() error = %v", err)
	}
	if !allBytesZero(source) {
		t.Fatal("ParseKeyringDocument() did not clear its source buffer")
	}
	if keyring.ActiveVersion() != 2 || !equalVersions(keyring.Versions(), []int16{1, 2}) {
		t.Fatalf("keyring versions = active %d, retained %v", keyring.ActiveVersion(), keyring.Versions())
	}
}

func TestParseKeyringDocumentRejectsAmbiguousOrInvalidDocuments(t *testing.T) {
	t.Parallel()

	key := encodedRoot(0xB1)
	entries := make([]string, 0, maximumKeyCount+1)
	for version := 1; version <= maximumKeyCount+1; version++ {
		entries = append(entries, fmt.Sprintf(`{"version":%d,"key":%q}`, version, key))
	}
	for _, test := range []struct {
		name     string
		document string
	}{
		{name: "empty"},
		{name: "null", document: `null`},
		{name: "array", document: `[]`},
		{name: "empty object", document: `{}`},
		{name: "unknown top-level field", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}],"secret":true}`, key)},
		{name: "unknown key field", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q,"name":"x"}]}`, key)},
		{name: "duplicate active field", document: fmt.Sprintf(`{"activeVersion":1,"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "case-folded duplicate active field", document: fmt.Sprintf(`{"activeVersion":1,"ActiveVersion":1,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "Unicode-folded duplicate active field", document: fmt.Sprintf(`{"activeVersion":1,"activeVer\u017fion":1,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "Unicode-folded duplicate keys field", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}],"key\u017f":[{"version":1,"key":%q}]}`, key, key)},
		{name: "Unicode-folded duplicate version field", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"ver\u017fion":1,"key":%q}]}`, key)},
		{name: "Unicode-folded duplicate key field", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q,"\u212Aey":%q}]}`, key, key)},
		{name: "trailing object", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]} {}`, key)},
		{name: "trailing scalar", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]} true`, key)},
		{name: "duplicate version", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q},{"version":1,"key":%q}]}`, key, key)},
		{name: "zero version", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":0,"key":%q}]}`, key)},
		{name: "negative version", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":-1,"key":%q}]}`, key)},
		{name: "overflow version", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":32768,"key":%q}]}`, key)},
		{name: "overflow active version", document: fmt.Sprintf(`{"activeVersion":32768,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "active version absent", document: fmt.Sprintf(`{"activeVersion":2,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "key missing", document: `{"activeVersion":1,"keys":[{"version":1}]}`},
		{name: "key null", document: `{"activeVersion":1,"keys":[{"version":1,"key":null}]}`},
		{name: "key not a string", document: `{"activeVersion":1,"keys":[{"version":1,"key":42}]}`},
		{name: "unpadded key", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, strings.TrimRight(key, "="))},
		{name: "URL alphabet key", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xFF}, sourceKeyBytes)))},
		{name: "short key", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, sourceKeyBytes-1)))},
		{name: "long key", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, sourceKeyBytes+1)))},
		{name: "too many keys", document: fmt.Sprintf(`{"activeVersion":1,"keys":[%s]}`, strings.Join(entries, ","))},
		{name: "oversized", document: strings.Repeat("x", maximumKeyringDocumentBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source := []byte(test.document)
			_, err := ParseKeyringDocument(source)
			if err == nil {
				t.Fatal("ParseKeyringDocument() unexpectedly succeeded")
			}
			if !allBytesZero(source) {
				t.Fatal("ParseKeyringDocument() did not clear a rejected source buffer")
			}
			if strings.Contains(err.Error(), key) {
				t.Fatal("ParseKeyringDocument() leaked key material")
			}
		})
	}
}

func FuzzParseKeyringDocumentNeverPanicsAndAlwaysClearsSource(f *testing.F) {
	f.Add([]byte(`{"activeVersion":1,"keys":[]}`))
	f.Add([]byte(fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, encodedRoot(0xC1))))
	f.Add([]byte(fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, sourceKeyBytes+1)))))
	f.Fuzz(func(t *testing.T, input []byte) {
		source := append([]byte(nil), input...)
		_, _ = ParseKeyringDocument(source)
		if !allBytesZero(source) {
			t.Fatal("ParseKeyringDocument() did not clear fuzz input")
		}
	})
}

func encodedRoot(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, sourceKeyBytes))
}

func allBytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func equalVersions(actual, expected []int16) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}
