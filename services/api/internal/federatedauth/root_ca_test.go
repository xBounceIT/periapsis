package federatedauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFederatedRootCAsUsesSystemRootsAndBoundedCustomBundle(t *testing.T) {
	systemOnly, err := LoadFederatedRootCAs("")
	if err != nil || systemOnly == nil {
		t.Fatalf("LoadFederatedRootCAs(system) = %v, %v", systemOnly, err)
	}

	bundle := filepath.Join(t.TempDir(), "federated-ca.pem")
	if err := os.WriteFile(bundle, testFederatedCACertificate(t), 0o600); err != nil {
		t.Fatal(err)
	}
	custom, err := LoadFederatedRootCAs("  " + bundle + "  ")
	if err != nil || custom == nil || len(custom.Subjects()) <= len(systemOnly.Subjects()) {
		t.Fatalf("LoadFederatedRootCAs(custom) subjects = %d, system = %d, error = %v", len(custom.Subjects()), len(systemOnly.Subjects()), err)
	}
}

func TestLoadFederatedRootCAsRejectsUnreadableMalformedAndOversizedBundles(t *testing.T) {
	directory := t.TempDir()
	malformed := filepath.Join(directory, "malformed.pem")
	partial := filepath.Join(directory, "partial.pem")
	nonCertificate := filepath.Join(directory, "non-certificate.pem")
	empty := filepath.Join(directory, "empty.pem")
	oversized := filepath.Join(directory, "oversized.pem")
	for path, contents := range map[string][]byte{
		malformed:      []byte("not a certificate"),
		partial:        append(testFederatedCACertificate(t), []byte("unexpected trailing data")...),
		nonCertificate: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}),
		empty:          {},
		oversized:      []byte(strings.Repeat("x", maximumFederatedCABundleBytes+1)),
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, path := range map[string]string{
		"missing":   filepath.Join(directory, "missing.pem"),
		"directory": directory,
		"empty":     empty,
		"malformed": malformed,
		"partial":   partial,
		"wrong PEM": nonCertificate,
		"oversized": oversized,
	} {
		t.Run(name, func(t *testing.T) {
			if roots, err := LoadFederatedRootCAs(path); !errors.Is(err, ErrInvalidOptions) || roots != nil {
				t.Fatalf("LoadFederatedRootCAs() = %v, %v", roots, err)
			}
		})
	}
}

func testFederatedCACertificate(t *testing.T) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	encoded, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Periapsis federated test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Periapsis federated test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
}
