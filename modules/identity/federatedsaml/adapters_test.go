package federatedsaml

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
	identity "github.com/periapsis-im/periapsis/modules/identity"
	dsig "github.com/russellhaering/goxmldsig"
)

type adapterKeySource struct {
	materials map[uint32]SPKeyMaterial
	calls     []SPKeyRequest
}

func (source *adapterKeySource) LoadSAMLSPKey(_ context.Context, request SPKeyRequest) (SPKeyMaterial, error) {
	source.calls = append(source.calls, request)
	material, ok := source.materials[request.KeyRevision]
	if !ok {
		return SPKeyMaterial{}, ErrSPKeyUnavailable
	}
	return material, nil
}

func TestLibraryCryptoAdapterSignsPinnedRedirectAndRejectsMismatchedMaterial(t *testing.T) {
	provider := identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: testID(1), ProviderID: testID(2)}
	bindingID := testID(3)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := adapterCertificate(t, privateKey, 101)
	source := &adapterKeySource{materials: map[uint32]SPKeyMaterial{7: {
		Provider: provider, BindingID: bindingID, KeyRevision: 7,
		Signer: privateKey, CertificateDER: [][]byte{certificate},
	}}}
	adapter, err := NewLibraryCryptoAdapter(source)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("SAMLRequest=" + base64.RawURLEncoding.EncodeToString(randomBytes(t, 32)))
	logoutMaterialID := testID(4)
	signature, err := adapter.SignRedirect(context.Background(), RedirectSignRequest{
		Provider: provider, BindingID: bindingID, KeyRevision: 7,
		LogoutMaterialID: logoutMaterialID, Algorithm: RedirectECDSASHA256, Payload: payload,
	})
	if err != nil {
		t.Fatalf("SignRedirect() error = %v", err)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(&privateKey.PublicKey, digest[:], signature) || len(source.calls) != 1 ||
		source.calls[0].Provider != provider || source.calls[0].BindingID != bindingID || source.calls[0].KeyRevision != 7 ||
		source.calls[0].LogoutMaterialID != logoutMaterialID {
		t.Fatal("redirect signature was not bound to the exact key revision")
	}
	clear(signature)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source.materials[7] = SPKeyMaterial{
		Provider: provider, BindingID: bindingID, KeyRevision: 7,
		Signer: privateKey, CertificateDER: [][]byte{adapterCertificate(t, otherKey, 102)},
	}
	if signature, err := adapter.SignRedirect(context.Background(), RedirectSignRequest{
		Provider: provider, BindingID: bindingID, KeyRevision: 7,
		Algorithm: RedirectECDSASHA256, Payload: payload,
	}); err == nil || len(signature) != 0 {
		clear(signature)
		t.Fatal("signer/certificate mismatch was accepted")
	}
}

func TestLibraryCryptoAdapterVerifiesOnlyExactSignedObject(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := adapterCertificate(t, privateKey, 201)
	metadata := compileTestMetadata(
		t, 55, "https://idp.example.test/entity", "https://idp.example.test/sso", "", certificate,
	)
	document := signedResponseDocument(t, privateKey, certificate, "_response")
	adapter, err := NewLibraryCryptoAdapter(&adapterKeySource{materials: map[uint32]SPKeyMaterial{}})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := adapter.VerifyXMLSignature(context.Background(), SignatureVerificationRequest{
		Document: document, ObjectKind: SignedObjectResponse, ObjectID: "_response", Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("VerifyXMLSignature() error = %v", err)
	}
	if proof.ObjectID != "_response" || proof.ReferenceURI != "#_response" || proof.MatchingCertificateCount != 1 ||
		proof.DocumentDigest != sha256.Sum256(document) || proof.SignatureAlgorithm != string(RedirectECDSASHA256) {
		t.Fatalf("unexpected signature proof: %+v", proof)
	}

	duplicateID := []byte(strings.Replace(
		string(document), "</samlp:Response>",
		`<saml:Assertion xmlns:saml="`+samlAssertionNamespace+`" ID="_response"></saml:Assertion></samlp:Response>`, 1,
	))
	duplicateKeyInfo := []byte(strings.Replace(
		string(document), "</ds:Signature>", "<ds:KeyInfo/></ds:Signature>", 1,
	))
	for name, hostile := range map[string]SignatureVerificationRequest{
		"duplicate ID":      {Document: duplicateID, ObjectKind: SignedObjectResponse, ObjectID: "_response", Metadata: metadata},
		"duplicate KeyInfo": {Document: duplicateKeyInfo, ObjectKind: SignedObjectResponse, ObjectID: "_response", Metadata: metadata},
		"wrong object":      {Document: document, ObjectKind: SignedObjectAssertion, ObjectID: "_response", Metadata: metadata},
		"wrong ID":          {Document: document, ObjectKind: SignedObjectResponse, ObjectID: "_other", Metadata: metadata},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := adapter.VerifyXMLSignature(context.Background(), hostile); err == nil {
				t.Fatal("hostile signed object unexpectedly accepted")
			}
		})
	}
}

func TestLibraryCryptoAdapterDecryptsOnlyPinnedModernProfile(t *testing.T) {
	provider := identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: testID(11), ProviderID: testID(12)}
	bindingID := testID(13)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	source := &adapterKeySource{materials: map[uint32]SPKeyMaterial{9: {
		Provider: provider, BindingID: bindingID, KeyRevision: 9, RSADecrypter: privateKey,
	}}}
	adapter, err := NewLibraryCryptoAdapter(source)
	if err != nil {
		t.Fatal(err)
	}
	assertion := []byte(`<saml:Assertion xmlns:saml="` + samlAssertionNamespace + `" ID="_assertion"></saml:Assertion>`)
	response := encryptedResponseDocument(t, &privateKey.PublicKey, assertion, aes128GCM)
	document := etree.NewDocument()
	if err := document.ReadFromBytes(response); err != nil {
		t.Fatal(err)
	}
	encrypted, count := findObjectByID(document.Root(), "_encrypted_data")
	if count != 1 {
		t.Fatalf("encrypted object count = %d", count)
	}
	interoperable, err := xmlenc.Decrypt(privateKey, encrypted.Copy())
	if err != nil || !bytes.Equal(interoperable, assertion) {
		clear(interoperable)
		t.Fatalf("crewjam XML Encryption interoperability failed: %v", err)
	}
	clear(interoperable)
	result, err := adapter.DecryptAssertion(context.Background(), DecryptionRequest{
		Response: response, ResponseID: "_response", EncryptedObjectID: "_encrypted_data",
		Provider: provider, BindingID: bindingID, AllowedKeyVersions: []uint32{9},
	})
	if err != nil {
		t.Fatalf("DecryptAssertion() error = %v", err)
	}
	if !bytes.Equal(result.Assertion, assertion) || result.KeyVersion != 9 ||
		result.ContentEncryptionAlgorithm != aes128GCM || result.KeyTransportAlgorithm != rsaOAEP11 {
		t.Fatalf("unexpected decryption proof: %+v", result)
	}
	clear(result.Assertion)

	unproved := encryptedResponseDocument(t, &privateKey.PublicKey, assertion, aes256GCM)
	before := len(source.calls)
	if _, err := adapter.DecryptAssertion(context.Background(), DecryptionRequest{
		Response: unproved, ResponseID: "_response", EncryptedObjectID: "_encrypted_data",
		Provider: provider, BindingID: bindingID, AllowedKeyVersions: []uint32{9},
	}); err == nil || len(source.calls) != before {
		t.Fatal("unproved content profile reached the private-key port")
	}
	if _, err := adapter.DecryptAssertion(context.Background(), DecryptionRequest{
		Response: response, ResponseID: "_response", EncryptedObjectID: "_encrypted_data",
		Provider: provider, BindingID: bindingID, AllowedKeyVersions: []uint32{9, 9},
	}); err == nil || len(source.calls) != before {
		t.Fatal("duplicate key revision reached the private-key port")
	}
}

func TestMetadataCacheIsRevisionExactBoundedAndCopySafe(t *testing.T) {
	now := fixtureTime
	source := &HTTPMetadataSource{maxEntries: 1, now: func() time.Time { return now }, cache: map[metadataCacheKey]metadataCacheEntry{}}
	first := metadataCacheKey{Provider: identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: testID(1), ProviderID: testID(2)}, BindingID: testID(3), Revision: 1}
	second := first
	second.Revision = 2
	source.store(first, metadataCacheEntry{document: []byte("first"), retrieved: now, freshUntil: now.Add(time.Hour)})
	loaded, ok := source.loadFresh(first, maximumMetadataAdapterBytes)
	if !ok {
		t.Fatal("fresh exact metadata cache entry missed")
	}
	loaded.document[0] = 'X'
	reloaded, ok := source.loadFresh(first, maximumMetadataAdapterBytes)
	if !ok || string(reloaded.document) != "first" {
		t.Fatal("metadata cache returned aliased document")
	}
	source.store(first, metadataCacheEntry{document: []byte("replacement"), retrieved: now, freshUntil: now.Add(2 * time.Hour)})
	if replaced, ok := source.loadFresh(first, maximumMetadataAdapterBytes); !ok || string(replaced.document) != "replacement" {
		t.Fatal("same-revision cache replacement was evicted")
	}
	source.store(second, metadataCacheEntry{document: []byte("second"), retrieved: now, freshUntil: now.Add(3 * time.Hour)})
	if _, ok := source.loadFresh(first, maximumMetadataAdapterBytes); ok {
		t.Fatal("bounded metadata cache retained an evicted revision")
	}
	if _, ok := source.loadFresh(second, len("second")-1); ok {
		t.Fatal("cache bypassed the caller's metadata byte ceiling")
	}
	if _, ok := source.loadFresh(second, maximumMetadataAdapterBytes); !ok {
		t.Fatal("lower caller byte ceiling evicted a reusable cache entry")
	}
}

func signedResponseDocument(t *testing.T, signer crypto.Signer, certificate []byte, id string) []byte {
	t.Helper()
	root := etree.NewElement("samlp:Response")
	root.CreateAttr("xmlns:samlp", samlProtocolNamespace)
	root.CreateAttr("ID", id)
	context, err := dsig.NewSigningContext(signer, [][]byte{certificate})
	if err != nil {
		t.Fatal(err)
	}
	context.IdAttribute = "ID"
	context.Prefix = "ds"
	context.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := context.SetSignatureMethod(string(RedirectECDSASHA256)); err != nil {
		t.Fatal(err)
	}
	signed, err := context.SignEnveloped(root)
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	document.SetRoot(signed)
	result, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func encryptedResponseDocument(t *testing.T, publicKey *rsa.PublicKey, plaintext []byte, contentAlgorithm string) []byte {
	t.Helper()
	contentKey := randomBytes(t, 16)
	defer clear(contentKey)
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := randomBytes(t, gcm.NonceSize())
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext := append(append([]byte(nil), nonce...), sealed...)
	clear(nonce)
	clear(sealed)
	defer clear(ciphertext)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, contentKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encryptedKey)
	return []byte(fmt.Sprintf(
		`<samlp:Response xmlns:samlp="%s" xmlns:saml="%s" xmlns:xenc="%s" xmlns:xenc11="%s" xmlns:ds="%s" ID="_response"><saml:EncryptedAssertion><xenc:EncryptedData Id="_encrypted_data" Type="%sElement"><xenc:EncryptionMethod Algorithm="%s"/><ds:KeyInfo><xenc:EncryptedKey Id="_encrypted_key"><xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/><xenc11:MGF Algorithm="%s"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`,
		samlProtocolNamespace, samlAssertionNamespace, xmlEncryptionNamespace, xmlEncryption11NS, xmlSignatureNamespace,
		xmlEncryptionNamespace, contentAlgorithm, rsaOAEP11, digestSHA256, mgf1SHA256,
		base64.StdEncoding.EncodeToString(encryptedKey), base64.StdEncoding.EncodeToString(ciphertext),
	))
}

func adapterCertificate(t *testing.T, signer crypto.Signer, serial int64) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "adapter test"},
		NotBefore: fixtureTime.Add(-time.Hour), NotAfter: fixtureTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	result := make([]byte, size)
	if _, err := rand.Read(result); err != nil {
		t.Fatal(err)
	}
	return result
}
