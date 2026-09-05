package serviceaccount

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParseCredentialKeyring(t *testing.T) {
	t.Parallel()

	first := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA1}, 32))
	second := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA2}, 32))
	document := fmt.Sprintf(`{"activeVersion":2,"keys":[{"version":1,"key":%q},{"version":2,"key":%q}]}`, first, second)
	keyring, err := ParseCredentialKeyring([]byte(document))
	if err != nil {
		t.Fatalf("ParseCredentialKeyring() error = %v", err)
	}
	if keyring.ActiveVersion() != 2 || !slicesEqual(keyring.VerificationVersions(), []int16{1, 2}) {
		t.Fatalf("keyring versions = active %d, verify %v", keyring.ActiveVersion(), keyring.VerificationVersions())
	}
}

func TestParseCredentialKeyringRejectsAmbiguousDocuments(t *testing.T) {
	t.Parallel()

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xB1}, 32))
	for _, test := range []struct {
		name     string
		document string
	}{
		{name: "empty"},
		{name: "unknown field", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}],"secret":true}`, key)},
		{name: "duplicate active member", document: fmt.Sprintf(`{"activeVersion":1,"activeVersion":2,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "case-folded active member", document: fmt.Sprintf(`{"activeVersion":1,"ActiveVersion":2,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "active member before Unicode-folded duplicate", document: fmt.Sprintf(`{"activeVersion":1,"activeVer\u017fion":1,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "Unicode-folded active member before duplicate", document: fmt.Sprintf(`{"activeVer\u017fion":1,"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "keys member before Unicode-folded duplicate", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}],"key\u017f":[{"version":1,"key":%q}]}`, key, key)},
		{name: "Unicode-folded keys member before duplicate", document: fmt.Sprintf(`{"activeVersion":1,"key\u017f":[{"version":1,"key":%q}],"keys":[{"version":1,"key":%q}]}`, key, key)},
		{name: "version member before Unicode-folded duplicate", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"ver\u017fion":1,"key":%q}]}`, key)},
		{name: "Unicode-folded version member before duplicate", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"ver\u017fion":1,"version":1,"key":%q}]}`, key)},
		{name: "key member before Unicode-folded duplicate", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q,"\u212Aey":%q}]}`, key, key)},
		{name: "Unicode-folded key member before duplicate", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"\u212Aey":%q,"key":%q}]}`, key, key)},
		{name: "duplicate nested key member", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q,"key":%q}]}`, key, key)},
		{name: "trailing value", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]} {}`, key)},
		{name: "duplicate version", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q},{"version":1,"key":%q}]}`, key, key)},
		{name: "active absent", document: fmt.Sprintf(`{"activeVersion":2,"keys":[{"version":1,"key":%q}]}`, key)},
		{name: "unpadded base64", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, strings.TrimRight(key, "="))},
		{name: "short key", document: fmt.Sprintf(`{"activeVersion":1,"keys":[{"version":1,"key":%q}]}`, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)))},
		{name: "oversized", document: strings.Repeat("x", maximumCredentialKeyringDocumentBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseCredentialKeyring([]byte(test.document)); err == nil {
				t.Fatal("ParseCredentialKeyring() unexpectedly succeeded")
			} else if strings.Contains(err.Error(), key) {
				t.Fatal("ParseCredentialKeyring() leaked key material in its error")
			}
		})
	}
}
