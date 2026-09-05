package federatedauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

func TestIdentitySAMLSessionMaterialProtectorRoundTripAndImmutableRowBinding(t *testing.T) {
	t.Parallel()
	keyring := samlSessionMaterialKeyring(t)
	protector, err := NewIdentitySAMLSessionMaterialProtector(keyring)
	if err != nil {
		t.Fatalf("NewIdentitySAMLSessionMaterialProtector() error = %v", err)
	}
	sealContext := SAMLSessionMaterialSealContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: serviceID(1), ProviderID: serviceID(2),
		},
		BindingID: serviceID(3), MaterialID: serviceID(4),
		// Legacy ownership values are deliberately outside the AAD.
		Anchor: SAMLSessionMaterialContinuationAnchor, AnchorID: serviceID(5),
	}
	material := federatedsaml.SessionMaterial{
		NameID:       "persistent-private-subject",
		NameIDFormat: federatedsaml.PersistentNameIDFormat,
		SessionIndex: "private-session-index",
	}
	protected, err := protector.SealSAMLSession(context.Background(), sealContext, material)
	if err != nil {
		t.Fatalf("SealSAMLSession() error = %v", err)
	}
	if protected.KeyVersion != 2 || len(protected.Ciphertext) <= samlSessionMaterialNonceBytes ||
		len(protected.Ciphertext) > maximumSAMLSessionMaterialEnvelope ||
		bytes.Contains(protected.Ciphertext, []byte(material.NameID)) ||
		bytes.Contains(protected.Ciphertext, []byte(material.SessionIndex)) {
		t.Fatalf("protected material has invalid shape: %s", protected)
	}
	openContext := federatedsaml.SessionMaterialContext{
		Provider: sealContext.Provider, BindingID: sealContext.BindingID, MaterialID: sealContext.MaterialID,
	}
	opened, err := protector.OpenSAMLSession(context.Background(), openContext, protected)
	if err != nil || opened != material {
		t.Fatalf("OpenSAMLSession() = %s, %v", opened, err)
	}

	for name, mutate := range map[string]func(*federatedsaml.SessionMaterialContext){
		"tenant":   func(value *federatedsaml.SessionMaterialContext) { value.Provider.TenantID = serviceID(10) },
		"provider": func(value *federatedsaml.SessionMaterialContext) { value.Provider.ProviderID = serviceID(11) },
		"binding":  func(value *federatedsaml.SessionMaterialContext) { value.BindingID = serviceID(12) },
		"material": func(value *federatedsaml.SessionMaterialContext) { value.MaterialID = serviceID(13) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := openContext
			mutate(&changed)
			opened, openErr := protector.OpenSAMLSession(context.Background(), changed, protected)
			if !errors.Is(openErr, federatedsaml.ErrLogoutArtifactRejected) ||
				opened != (federatedsaml.SessionMaterial{}) {
				t.Fatalf("OpenSAMLSession() = %s, %v", opened, openErr)
			}
		})
	}

	tampered := federatedsaml.ProtectedSessionMaterial{
		KeyVersion: protected.KeyVersion, Ciphertext: append([]byte(nil), protected.Ciphertext...),
	}
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
	if opened, openErr := protector.OpenSAMLSession(context.Background(), openContext, tampered); !errors.Is(openErr, federatedsaml.ErrLogoutArtifactRejected) {
		t.Fatalf("tampered OpenSAMLSession() = %s, %v", opened, openErr)
	}
}

func TestIdentitySAMLSessionMaterialProtectorOpensPurposeSeparatedDirectPlatformMaterial(t *testing.T) {
	t.Parallel()
	keyring := samlSessionMaterialKeyring(t)
	protector, err := NewIdentitySAMLSessionMaterialProtector(keyring)
	if err != nil {
		t.Fatal(err)
	}
	material := federatedsaml.SessionMaterial{
		NameID: "direct-platform-subject", NameIDFormat: federatedsaml.PersistentNameIDFormat,
		SessionIndex: "direct-platform-session-index",
	}
	plaintext, ok := encodeSAMLSessionMaterial(material)
	if !ok {
		t.Fatal("encodeSAMLSessionMaterial() rejected direct fixture")
	}
	defer clear(plaintext)
	directContext := identity.DirectPlatformSAMLSessionMaterialContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: serviceID(40),
		},
		MaterialID: serviceID(41), PlatformLoginRevision: 7,
	}
	envelope, err := keyring.EncryptDirectPlatformSAMLSessionMaterial(directContext, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	serialized := append(append([]byte(nil), envelope.Nonce[:]...), envelope.Ciphertext...)
	defer clear(serialized)
	openContext := federatedsaml.SessionMaterialContext{
		Authority: federatedsaml.DirectPlatformCeremonyAuthority,
		Provider:  directContext.Provider, MaterialID: directContext.MaterialID,
		PlatformLoginRevision: directContext.PlatformLoginRevision,
	}
	opened, err := protector.OpenSAMLSession(context.Background(), openContext, federatedsaml.ProtectedSessionMaterial{
		KeyVersion: uint32(envelope.KeyVersion), Ciphertext: serialized,
	})
	if err != nil || opened != material {
		t.Fatalf("OpenSAMLSession() = %s, %v", opened, err)
	}

	tenantContext := federatedsaml.SessionMaterialContext{
		Authority: federatedsaml.TenantCeremonyAuthority,
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: serviceID(42), ProviderID: directContext.Provider.ProviderID,
		},
		BindingID: serviceID(43), MaterialID: directContext.MaterialID,
	}
	if cross, crossErr := protector.OpenSAMLSession(context.Background(), tenantContext, federatedsaml.ProtectedSessionMaterial{
		KeyVersion: uint32(envelope.KeyVersion), Ciphertext: serialized,
	}); !errors.Is(crossErr, federatedsaml.ErrLogoutArtifactRejected) || cross != (federatedsaml.SessionMaterial{}) {
		t.Fatalf("tenant cross-open = %s, %v", cross, crossErr)
	}
}

func TestIdentitySAMLSessionMaterialProtectorRejectsMalformedInputsAndCancellation(t *testing.T) {
	t.Parallel()
	if _, err := NewIdentitySAMLSessionMaterialProtector(identity.Keyring{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("empty keyring error = %v", err)
	}
	protector, err := NewIdentitySAMLSessionMaterialProtector(samlSessionMaterialKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	validSealContext := SAMLSessionMaterialSealContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: serviceID(21), ProviderID: serviceID(22),
		},
		BindingID: serviceID(23), MaterialID: serviceID(24),
	}
	validMaterial := federatedsaml.SessionMaterial{
		NameID: "subject", NameIDFormat: federatedsaml.PersistentNameIDFormat, SessionIndex: "session",
	}
	invalidContexts := []SAMLSessionMaterialSealContext{
		{},
		{Provider: validSealContext.Provider, BindingID: validSealContext.BindingID, AnchorID: serviceID(25)},
	}
	for index, protection := range invalidContexts {
		if protected, sealErr := protector.SealSAMLSession(context.Background(), protection, validMaterial); !errors.Is(sealErr, ErrAuthentication) {
			clear(protected.Ciphertext)
			t.Fatalf("context %d error = %v", index, sealErr)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if protected, sealErr := protector.SealSAMLSession(cancelled, validSealContext, validMaterial); !errors.Is(sealErr, ErrAuthentication) {
		clear(protected.Ciphertext)
		t.Fatalf("cancelled seal error = %v", sealErr)
	}
	openContext := federatedsaml.SessionMaterialContext{
		Provider: validSealContext.Provider, BindingID: validSealContext.BindingID, MaterialID: validSealContext.MaterialID,
	}
	for name, protected := range map[string]federatedsaml.ProtectedSessionMaterial{
		"empty":        {},
		"unknown key":  {KeyVersion: 3, Ciphertext: bytes.Repeat([]byte{1}, 32)},
		"wide version": {KeyVersion: uint32(^uint16(0)), Ciphertext: bytes.Repeat([]byte{1}, 32)},
		"short":        {KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{1}, samlSessionMaterialNonceBytes)},
		"oversized":    {KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{1}, maximumSAMLSessionMaterialEnvelope+1)},
	} {
		if opened, openErr := protector.OpenSAMLSession(context.Background(), openContext, protected); !errors.Is(openErr, federatedsaml.ErrLogoutArtifactRejected) {
			t.Fatalf("%s OpenSAMLSession() = %s, %v", name, opened, openErr)
		}
	}
}

func TestSAMLSessionMaterialCanonicalDocumentRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	valid := federatedsaml.SessionMaterial{
		NameID: "subject", NameIDFormat: federatedsaml.PersistentNameIDFormat, SessionIndex: "session",
	}
	document, ok := encodeSAMLSessionMaterial(valid)
	if !ok {
		t.Fatal("valid document rejected")
	}
	defer clear(document)
	decoded, ok := decodeSAMLSessionMaterial(document)
	if !ok || decoded != valid {
		t.Fatalf("decodeSAMLSessionMaterial() = %s, %t", decoded, ok)
	}

	invalidMaterials := []federatedsaml.SessionMaterial{
		{},
		{NameID: "subject"},
		{NameID: "subject", NameIDFormat: "urn:unsupported", SessionIndex: "session"},
		{NameID: " subject", NameIDFormat: federatedsaml.PersistentNameIDFormat},
		{NameID: string([]byte{0xff}), NameIDFormat: federatedsaml.PersistentNameIDFormat},
		{SessionIndex: strings.Repeat("x", maximumSAMLSessionIndexBytes+1)},
	}
	for index, material := range invalidMaterials {
		if encoded, accepted := encodeSAMLSessionMaterial(material); accepted {
			clear(encoded)
			t.Fatalf("invalid material %d accepted", index)
		}
	}

	mutations := map[string][]byte{
		"empty":      {},
		"truncated":  append([]byte(nil), document[:len(document)-1]...),
		"trailing":   append(append([]byte(nil), document...), 0),
		"bad prefix": append([]byte(nil), document...),
		"wide field": append([]byte(nil), document...),
	}
	mutations["bad prefix"][0] ^= 1
	binary.BigEndian.PutUint32(mutations["wide field"][len(samlSessionMaterialDocumentPrefix):], ^uint32(0))
	for name, malformed := range mutations {
		if decoded, accepted := decodeSAMLSessionMaterial(malformed); accepted {
			t.Fatalf("%s decoded as %s", name, decoded)
		}
	}
}

func TestIdentitySAMLSessionMaterialProtectorFormattingRedacts(t *testing.T) {
	t.Parallel()
	protector, err := NewIdentitySAMLSessionMaterialProtector(samlSessionMaterialKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	const canary = "saml-session-material-private-canary"
	values := []any{
		protector,
		identity.SAMLSessionMaterialEnvelope{Ciphertext: []byte(canary)},
		federatedsaml.ProtectedSessionMaterial{Ciphertext: []byte(canary)},
		federatedsaml.SessionMaterial{NameID: canary, NameIDFormat: federatedsaml.PersistentNameIDFormat, SessionIndex: canary},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func samlSessionMaterialKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	rootOne := bytes.Repeat([]byte{0x61}, 32)
	rootTwo := bytes.Repeat([]byte{0x62}, 32)
	keyring, err := identity.NewKeyring(2, map[int16][]byte{1: rootOne, 2: rootTwo})
	clear(rootOne)
	clear(rootTwo)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}
