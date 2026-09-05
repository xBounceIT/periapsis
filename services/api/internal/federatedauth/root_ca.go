package federatedauth

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"strings"
)

const maximumFederatedCABundleBytes = 1024 * 1024

// LoadFederatedRootCAs returns an owned system trust pool, optionally extended
// with a deployment-mounted PEM bundle. Tenant configuration cannot select or
// widen this trust root. Errors deliberately omit filesystem and certificate
// details because deployment paths can disclose infrastructure topology.
func LoadFederatedRootCAs(bundleFile string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, ErrInvalidOptions
	}
	roots = roots.Clone()
	bundleFile = strings.TrimSpace(bundleFile)
	if bundleFile == "" {
		return roots, nil
	}

	file, err := os.Open(bundleFile)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumFederatedCABundleBytes {
		return nil, ErrInvalidOptions
	}
	document, err := io.ReadAll(io.LimitReader(file, maximumFederatedCABundleBytes+1))
	if err != nil || len(document) == 0 || len(document) > maximumFederatedCABundleBytes {
		clear(document)
		return nil, ErrInvalidOptions
	}
	defer clear(document)
	if !validCertificatePEM(document) {
		return nil, ErrInvalidOptions
	}
	if !roots.AppendCertsFromPEM(document) {
		return nil, ErrInvalidOptions
	}
	return roots, nil
}

func validCertificatePEM(document []byte) bool {
	rest := document
	parsed := false
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		parsed = true
		rest = remainder
	}
	return parsed
}
