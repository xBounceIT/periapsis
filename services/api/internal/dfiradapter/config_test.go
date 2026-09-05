package dfiradapter

import (
	"fmt"
	"strings"
	"testing"
)

func TestLoadConfigRequiresExplicitBoundedDependencies(t *testing.T) {
	t.Parallel()
	values := validDevelopmentEnvironment()
	config, err := loadConfigFrom("development", mapConfigSource(values, nil))
	if err != nil {
		t.Fatalf("loadConfigFrom() error = %v", err)
	}
	if config.Storage.Bucket() != "periapsis-evidence" ||
		config.Storage.MaximumObjectBytes() != SinglePutMaximumBytes {
		t.Fatal("configuration lost the bucket or portable single-PUT cap")
	}
	formatted := fmt.Sprintf("%#v %#v %#v", config, config.Storage, config.Scanner)
	for _, secret := range []string{"ACCESS-CANARY", "SECRET-CANARY-0123456789", "storage.example", "clamd.sock"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("configuration formatter exposed %q", secret)
		}
	}
}

func TestLoadConfigValidatesOptionalTicketExportBucketOwner(t *testing.T) {
	t.Parallel()
	values := with(
		validDevelopmentEnvironment(),
		"PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER",
		"123456789012",
	)
	config, err := loadConfigFrom("development", mapConfigSource(values, nil))
	if err != nil || config.Storage.expectedOwner != "123456789012" {
		t.Fatalf("expected-owner configuration = %q, %v", config.Storage.expectedOwner, err)
	}
	for _, value := range []string{"", "123", "12345678901a", " 123456789012"} {
		if _, err := loadConfigFrom(
			"development",
			mapConfigSource(
				with(validDevelopmentEnvironment(), "PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER", value),
				nil,
			),
		); err == nil {
			t.Fatalf("invalid expected owner %q succeeded", value)
		}
	}
}

func TestLoadConfigProductionUsesOnlyFileCredentialsAndTLS(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		"PERIAPSIS_S3_ENDPOINT":           "https://storage.example",
		"PERIAPSIS_S3_PUBLIC_ENDPOINT":    "https://downloads.example",
		"PERIAPSIS_S3_REGION":             "eu-south-1",
		"PERIAPSIS_S3_BUCKET":             "periapsis-evidence",
		"PERIAPSIS_S3_ACCESS_KEY_FILE":    "/run/secrets/dfir-access",
		"PERIAPSIS_S3_SECRET_KEY_FILE":    "/run/secrets/dfir-secret",
		"PERIAPSIS_DFIR_SCANNER_ENDPOINT": "tls://scanner.example:3310",
	}
	files := map[string][]byte{
		"/run/secrets/dfir-access": []byte("ACCESS-CANARY\n"),
		"/run/secrets/dfir-secret": []byte("SECRET-CANARY-0123456789\n"),
	}
	if _, err := loadConfigFrom("production", mapConfigSource(values, files)); err != nil {
		t.Fatalf("production file configuration rejected: %v", err)
	}

	hostile := []map[string]string{
		with(values, "PERIAPSIS_S3_ACCESS_KEY", "direct-canary"),
		with(values, "PERIAPSIS_S3_ENDPOINT", "http://storage.example"),
		with(values, "PERIAPSIS_S3_PUBLIC_ENDPOINT", "http://downloads.example"),
		with(values, "PERIAPSIS_DFIR_SCANNER_ENDPOINT", "tcp://scanner.example:3310"),
		with(values, "PERIAPSIS_S3_ENDPOINT", "https://169.254.169.254"),
		with(values, "PERIAPSIS_S3_ENDPOINT", "https://127.0.0.1"),
	}
	for index, candidate := range hostile {
		if _, err := loadConfigFrom("production", mapConfigSource(candidate, files)); err == nil {
			t.Fatalf("hostile production configuration %d succeeded", index)
		}
	}

	files["/run/secrets/dfir-access"] = []byte("ACCESS-CANARY\n\n")
	if _, err := loadConfigFrom("production", mapConfigSource(values, files)); err == nil {
		t.Fatal("production secret with ambiguous surrounding whitespace succeeded")
	}
}

func TestLoadConfigRejectsAmbiguousSecretsLimitsAndDestinations(t *testing.T) {
	t.Parallel()
	base := validDevelopmentEnvironment()
	testCases := []map[string]string{
		with(base, "PERIAPSIS_S3_ACCESS_KEY_FILE", "/secret"),
		with(base, "PERIAPSIS_DFIR_MAX_OBJECT_BYTES", "5000000001"),
		with(base, "PERIAPSIS_DFIR_MAX_OBJECT_BYTES", "0500000000"),
		with(base, "PERIAPSIS_S3_ENDPOINT", "https://STORAGE.example"),
		with(base, "PERIAPSIS_S3_ENDPOINT", "https://storage.example/"),
		with(base, "PERIAPSIS_S3_ENDPOINT", "https://2130706433"),
		with(base, "PERIAPSIS_S3_ENDPOINT", "https://0x7f.0x0.0x0.0x1"),
		with(base, "PERIAPSIS_S3_PUBLIC_ENDPOINT", "https://downloads.example/path"),
		with(base, "PERIAPSIS_S3_BUCKET", "192.168.001.001"),
		with(base, "PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS", "127.0.0.1/32"),
		with(base, "PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS", "10.0.0.0/7"),
		with(base, "PERIAPSIS_DFIR_SCANNER_ENDPOINT", "unix:///run/../clamd.sock"),
	}
	for index, values := range testCases {
		if _, err := loadConfigFrom("development", mapConfigSource(values, nil)); err == nil {
			t.Fatalf("invalid configuration %d succeeded", index)
		}
	}

	badFiles := map[string][]byte{"/secret": []byte("ACCESS-CANARY\n\n")}
	if _, err := loadConfigFrom(
		"production",
		mapConfigSource(map[string]string{
			"PERIAPSIS_S3_ENDPOINT":           "https://storage.example",
			"PERIAPSIS_S3_REGION":             "eu-south-1",
			"PERIAPSIS_S3_BUCKET":             "periapsis-evidence",
			"PERIAPSIS_S3_ACCESS_KEY_FILE":    "/secret",
			"PERIAPSIS_S3_SECRET_KEY_FILE":    "relative-secret",
			"PERIAPSIS_DFIR_SCANNER_ENDPOINT": "unix:///run/clamav/clamd.sock",
		}, badFiles),
	); err == nil {
		t.Fatal("non-canonical secret file configuration succeeded")
	}
}

func validDevelopmentEnvironment() map[string]string {
	return map[string]string{
		"PERIAPSIS_S3_ENDPOINT":           "https://storage.example",
		"PERIAPSIS_S3_REGION":             "eu-south-1",
		"PERIAPSIS_S3_BUCKET":             "periapsis-evidence",
		"PERIAPSIS_S3_ACCESS_KEY":         "ACCESS-CANARY",
		"PERIAPSIS_S3_SECRET_KEY":         "SECRET-CANARY-0123456789",
		"PERIAPSIS_DFIR_SCANNER_ENDPOINT": "unix:///run/clamav/clamd.sock",
	}
}

func mapConfigSource(values map[string]string, files map[string][]byte) configSource {
	return configSource{
		lookup: func(name string) (string, bool) {
			value, present := values[name]
			return value, present
		},
		readFile: func(name string) ([]byte, error) {
			value, present := files[name]
			if !present {
				return nil, fmt.Errorf("missing test file")
			}
			return append([]byte(nil), value...), nil
		},
	}
}

func with(source map[string]string, key, value string) map[string]string {
	result := make(map[string]string, len(source)+1)
	for name, existing := range source {
		result[name] = existing
	}
	result[key] = value
	return result
}
