package main

import (
	"testing"
	"time"
)

func TestConfiguredOIDCFlowPolicyAppliesDeploymentBounds(t *testing.T) {
	policy := configuredOIDCFlowPolicy(12*time.Second, 150*time.Second)

	if policy.OperationTimeout != 12*time.Second || policy.ClockSkew != 150*time.Second {
		t.Fatalf("configured OIDC policy = timeout %s, skew %s", policy.OperationTimeout, policy.ClockSkew)
	}
}

func TestConfiguredTenantOIDCRedirectsAreDeploymentOwned(t *testing.T) {
	redirectURI, postLogoutRedirectURI := configuredTenantOIDCRedirects("https://app.example.test:8443")

	if redirectURI != "https://app.example.test:8443/api/v1/auth/federated/oidc/callback" ||
		postLogoutRedirectURI != "https://app.example.test:8443/signed-out" {
		t.Fatalf("configured tenant OIDC redirects = %q, %q", redirectURI, postLogoutRedirectURI)
	}
}
