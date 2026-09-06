package config

import (
	"strconv"
	"testing"
)

func TestAPIRateLimitBoundsBeforeNarrowing(t *testing.T) {
	variables := []string{
		"PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS",
		"PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS",
		"PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS",
	}
	for _, variable := range variables {
		t.Run(variable, func(t *testing.T) {
			t.Setenv("PERIAPSIS_ENV", "development")
			for _, name := range variables {
				t.Setenv(name, "50")
			}
			for _, value := range []string{"-1", "0", "101", "2147483647", "2147483648", "4294967297", "-4294967295", "9223372036854775807", "9223372036854775808"} {
				t.Setenv(variable, value)
				if _, err := Load(); err == nil {
					t.Fatal("invalid rate limit survived configuration validation")
				}
			}
			for _, value := range []int32{1, 100} {
				t.Setenv(variable, strconv.FormatInt(int64(value), 10))
				cfg, err := Load()
				if err != nil {
					t.Fatal(err)
				}
				actual := map[string]int32{
					variables[0]: cfg.APIRateLimitPolicy.NetworkRequestsPerSecond,
					variables[1]: cfg.APIRateLimitPolicy.CredentialRequestsPerSecond,
					variables[2]: cfg.APIRateLimitPolicy.TenantSubjectRequestsPerSecond,
				}
				if actual[variable] != value {
					t.Fatal("valid rate-limit boundary changed during conversion")
				}
			}
		})
	}
}
