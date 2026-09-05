package federatedsaml

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestMaximumPOSTFormBytesAdmitsWorstCasePercentEscapedEnvelope(t *testing.T) {
	limits := DefaultLimits()
	maximum, err := MaximumPOSTFormBytes(limits)
	if err != nil {
		t.Fatalf("MaximumPOSTFormBytes() error = %v", err)
	}

	document := bytes.Repeat([]byte{0xff}, limits.MaxDecodedResponseBytes)
	encodedResponse := base64.StdEncoding.EncodeToString(document)
	if len(encodedResponse) != limits.MaxEncodedResponseBytes {
		t.Fatalf("encoded response bytes = %d, want %d", len(encodedResponse), limits.MaxEncodedResponseBytes)
	}
	relayState := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, minimumOpaqueBytes))
	if len(relayState) != canonicalRelayStateBytes {
		t.Fatalf("relay state bytes = %d, want %d", len(relayState), canonicalRelayStateBytes)
	}
	raw := []byte(
		"SAMLResponse=" + percentEscapeEveryByte(encodedResponse) +
			"&RelayState=" + percentEscapeEveryByte(relayState),
	)
	if len(raw) != maximum {
		t.Fatalf("worst-case raw form bytes = %d, want %d", len(raw), maximum)
	}

	decoded, observedRelay, err := parsePOSTForm("application/x-www-form-urlencoded", raw, limits)
	if err != nil {
		t.Fatalf("parsePOSTForm() error = %v", err)
	}
	if !bytes.Equal(decoded, document) || observedRelay != relayState {
		t.Fatal("parsePOSTForm() changed the maximum valid envelope")
	}
	clear(decoded)

	oversized := append(append([]byte(nil), raw...), 'A')
	if _, _, err := parsePOSTForm("application/x-www-form-urlencoded", oversized, limits); err == nil {
		t.Fatal("parsePOSTForm() accepted a raw form one byte over the derived ceiling")
	}
}

func TestMaximumPOSTFormBytesRejectsInvalidLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxEncodedResponseBytes = 0
	if maximum, err := MaximumPOSTFormBytes(limits); maximum != 0 || !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("MaximumPOSTFormBytes() = %d, %v", maximum, err)
	}
}

func percentEscapeEveryByte(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(3 * len(value))
	for index := 0; index < len(value); index++ {
		escaped.WriteByte('%')
		escaped.WriteByte(hexadecimal[value[index]>>4])
		escaped.WriteByte(hexadecimal[value[index]&0x0f])
	}
	return escaped.String()
}
