package identityprovider

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	federationSAMLRSAKeyBits          = 3072
	federationSAMLCertificateLifetime = 397 * 24 * time.Hour
	federationSAMLCertificateBackdate = 5 * time.Minute
)

// GenerateFederationSAMLSPCredential creates one provider-specific private
// key and self-signed, non-CA leaf certificate with the OS CSPRNG. The
// returned plaintext belongs to the caller and must be destroyed after
// validation and keyring encryption.
func GenerateFederationSAMLSPCredential(
	request FederationSAMLSPCredentialGenerationRequest,
) (bundle FederationSAMLSPCredentialBundle, err error) {
	if !validFederationSAMLSPCredentialGenerationRequest(request) {
		return FederationSAMLSPCredentialBundle{}, errors.New("tenant SAML SP credential generation request is invalid")
	}
	privateKey, err := generateFederationSAMLPrivateKey(request.RedirectSignatureAlgorithm)
	if err != nil {
		return FederationSAMLSPCredentialBundle{}, errors.New("generate tenant SAML SP private key")
	}
	defer destroyFederationSAMLPrivateKey(privateKey)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return FederationSAMLSPCredentialBundle{}, errors.New("encode tenant SAML SP private key")
	}
	bundle = FederationSAMLSPCredentialBundle{PrivateKeyPKCS8: pkcs8}
	defer func() {
		if err != nil {
			bundle.Destroy()
		}
	}()
	serial, err := federationSAMLPositiveSerial()
	if err != nil {
		return FederationSAMLSPCredentialBundle{}, errors.New("generate tenant SAML SP certificate serial")
	}
	entityURI, err := url.Parse(request.SPEntityID)
	if err != nil {
		return FederationSAMLSPCredentialBundle{}, errors.New("parse tenant SAML SP entity identifier")
	}
	publicKey := privateKey.(crypto.Signer).Public()
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return FederationSAMLSPCredentialBundle{}, errors.New("encode tenant SAML SP public key")
	}
	subjectKeyID := sha256.Sum256(publicKeyDER)
	keyUsage := x509.KeyUsageDigitalSignature
	if _, rsaKey := privateKey.(*rsa.PrivateKey); rsaKey {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	certificate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Periapsis"},
			CommonName:   "Periapsis tenant SAML service provider",
		},
		NotBefore:             request.GeneratedAt.Add(-federationSAMLCertificateBackdate).Truncate(time.Second),
		NotAfter:              request.GeneratedAt.Add(federationSAMLCertificateLifetime).Truncate(time.Second),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{entityURI},
		SubjectKeyId:          append([]byte(nil), subjectKeyID[:20]...),
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificate, certificate, publicKey, privateKey)
	clear(publicKeyDER)
	clear(subjectKeyID[:])
	if err != nil {
		return FederationSAMLSPCredentialBundle{}, errors.New("create tenant SAML SP certificate")
	}
	bundle.CertificateDER = [][]byte{certificateDER}
	return bundle, nil
}

func generateFederationSAMLPrivateKey(algorithm federatedsaml.RedirectSignatureAlgorithm) (any, error) {
	switch algorithm {
	case federatedsaml.RedirectRSASHA256, federatedsaml.RedirectRSASHA384, federatedsaml.RedirectRSASHA512:
		return rsa.GenerateKey(rand.Reader, federationSAMLRSAKeyBits)
	case federatedsaml.RedirectECDSASHA256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case federatedsaml.RedirectECDSASHA384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case federatedsaml.RedirectECDSASHA512:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, errors.New("unsupported tenant SAML redirect signature algorithm")
	}
}

func federationSAMLPositiveSerial() (*big.Int, error) {
	encoded := make([]byte, 20)
	if _, err := rand.Read(encoded); err != nil {
		clear(encoded)
		return nil, err
	}
	encoded[0] &= 0x7f
	allZero := true
	for _, value := range encoded {
		allZero = allZero && value == 0
	}
	if allZero {
		encoded[len(encoded)-1] = 1
	}
	serial := new(big.Int).SetBytes(encoded)
	clear(encoded)
	return serial, nil
}

func validFederationSAMLSPCredentialGenerationRequest(
	request FederationSAMLSPCredentialGenerationRequest,
) bool {
	return validFederationRedirectAlgorithm(request.RedirectSignatureAlgorithm) &&
		validCanonicalAbsoluteURI(request.SPEntityID) &&
		validFederationSAMLAdministrationInstant(request.GeneratedAt)
}

func validGeneratedFederationSAMLSPCredential(
	bundle FederationSAMLSPCredentialBundle,
	request FederationSAMLSPCredentialGenerationRequest,
) bool {
	if !validFederationSAMLSPCredentialGenerationRequest(request) ||
		!validFederationSAMLSPCredentialSize(bundle.PrivateKeyPKCS8, bundle.CertificateDER) ||
		len(bundle.CertificateDER) != 1 {
		return false
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(bundle.PrivateKeyPKCS8)
	if err != nil || !federationSAMLPrivateKeyMatchesAlgorithm(privateKey, request.RedirectSignatureAlgorithm) {
		return false
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return false
	}
	certificate, err := x509.ParseCertificate(bundle.CertificateDER[0])
	if err != nil || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 ||
		certificate.SerialNumber.BitLen() > 159 || !certificate.BasicConstraintsValid || certificate.IsCA ||
		!certificate.NotBefore.Equal(request.GeneratedAt.Add(-federationSAMLCertificateBackdate).Truncate(time.Second)) ||
		!certificate.NotAfter.Equal(request.GeneratedAt.Add(federationSAMLCertificateLifetime).Truncate(time.Second)) ||
		!bytes.Equal(certificate.RawSubject, certificate.RawIssuer) || len(certificate.URIs) != 1 ||
		certificate.URIs[0].String() != request.SPEntityID || len(certificate.DNSNames) != 0 ||
		len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 ||
		len(certificate.ExtKeyUsage) != 0 || len(certificate.UnknownExtKeyUsage) != 0 ||
		certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil {
		return false
	}
	wantUsage := x509.KeyUsageDigitalSignature
	if _, rsaKey := privateKey.(*rsa.PrivateKey); rsaKey {
		wantUsage |= x509.KeyUsageKeyEncipherment
	}
	if certificate.KeyUsage != wantUsage {
		return false
	}
	wantPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false
	}
	defer clear(wantPublic)
	gotPublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	defer clear(gotPublic)
	return err == nil && bytes.Equal(wantPublic, gotPublic)
}

func federationSAMLPrivateKeyMatchesAlgorithm(
	privateKey any,
	algorithm federatedsaml.RedirectSignatureAlgorithm,
) bool {
	switch algorithm {
	case federatedsaml.RedirectRSASHA256, federatedsaml.RedirectRSASHA384, federatedsaml.RedirectRSASHA512:
		key, ok := privateKey.(*rsa.PrivateKey)
		return ok && key != nil && key.N != nil && key.N.BitLen() == federationSAMLRSAKeyBits &&
			key.E == 65537 && key.Validate() == nil
	case federatedsaml.RedirectECDSASHA256:
		return federationSAMLECDSAKeyUsesCurve(privateKey, elliptic.P256())
	case federatedsaml.RedirectECDSASHA384:
		return federationSAMLECDSAKeyUsesCurve(privateKey, elliptic.P384())
	case federatedsaml.RedirectECDSASHA512:
		return federationSAMLECDSAKeyUsesCurve(privateKey, elliptic.P521())
	default:
		return false
	}
}

func federationSAMLECDSAKeyUsesCurve(privateKey any, curve elliptic.Curve) bool {
	key, ok := privateKey.(*ecdsa.PrivateKey)
	return ok && key != nil && key.Curve != nil && key.D != nil && key.PublicKey.X != nil && key.PublicKey.Y != nil &&
		key.Curve.Params().Name == curve.Params().Name && key.Curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) &&
		key.D.Sign() > 0 && key.D.Cmp(key.Curve.Params().N) < 0
}

func destroyFederationSAMLPrivateKey(privateKey any) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if key == nil {
			return
		}
		key.D.SetInt64(0)
		for _, prime := range key.Primes {
			prime.SetInt64(0)
		}
		if key.Precomputed.Dp != nil {
			key.Precomputed.Dp.SetInt64(0)
		}
		if key.Precomputed.Dq != nil {
			key.Precomputed.Dq.SetInt64(0)
		}
		if key.Precomputed.Qinv != nil {
			key.Precomputed.Qinv.SetInt64(0)
		}
		for index := range key.Precomputed.CRTValues {
			if key.Precomputed.CRTValues[index].Exp != nil {
				key.Precomputed.CRTValues[index].Exp.SetInt64(0)
			}
			if key.Precomputed.CRTValues[index].Coeff != nil {
				key.Precomputed.CRTValues[index].Coeff.SetInt64(0)
			}
			if key.Precomputed.CRTValues[index].R != nil {
				key.Precomputed.CRTValues[index].R.SetInt64(0)
			}
		}
	case *ecdsa.PrivateKey:
		if key != nil && key.D != nil {
			key.D.SetInt64(0)
		}
	}
}
