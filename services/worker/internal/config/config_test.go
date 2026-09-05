package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const validIdentityKeyring = `{"activeVersion":1,"keys":[{"version":1,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`

func setDevelopmentIdentityKeyring(t *testing.T) {
	t.Helper()
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING", validIdentityKeyring)
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING_FILE", "")
}

func TestLoadUsesSafeDevelopmentDefaults(t *testing.T) {
	setDevelopmentIdentityKeyring(t)
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_WORKER_ADDR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Address != ":8082" {
		t.Fatalf("Address = %q, want :8082", cfg.Address)
	}
	if cfg.AuthCleanupBatch != 250 || cfg.AuthCleanupInterval != 5*time.Minute {
		t.Fatalf("authentication cleanup defaults = %d/%s", cfg.AuthCleanupBatch, cfg.AuthCleanupInterval)
	}
	if cfg.DatabaseTimeout != 5*time.Second || cfg.PollInterval != 5*time.Second {
		t.Fatalf("database timing defaults = %s/%s", cfg.DatabaseTimeout, cfg.PollInterval)
	}
	if cfg.DFIRScanBatchSize != 4 || cfg.DFIRScanLeaseDuration != 10*time.Minute ||
		cfg.DFIRScanOperationTimeout != 6*time.Minute || cfg.DFIRScanUploadPollDelay != 5*time.Second ||
		cfg.DFIRCleanupBatchSize != 16 || cfg.DFIRCleanupLeaseDuration != 2*time.Minute ||
		cfg.DFIRCleanupDeleteTimeout != 30*time.Second {
		t.Fatalf("unsafe DFIR runtime defaults: %+v", cfg)
	}
	if len(cfg.FederatedPrivateEgressCIDRs) != 0 || len(cfg.FederatedAllowedHTTPSPorts) != 0 ||
		cfg.FederatedCABundleFile != "" || cfg.FederatedMaxConcurrent != 16 ||
		cfg.FederatedOperationTimeout != 20*time.Second || cfg.OIDCMaintenanceBatchSize != 12 ||
		cfg.OIDCMaintenanceLeaseSafety != 5*time.Second || cfg.OIDCMaintenancePollInterval != 2*time.Second {
		t.Fatalf("unsafe OIDC maintenance defaults: %+v", cfg)
	}
	if cfg.TicketRuntimeServiceAccountID.String() != "00000000-0000-0000-0000-000000000000" ||
		!filepath.IsAbs(cfg.TicketExportSpoolDirectory) || cfg.TicketExportExpectedOwner != "" {
		t.Fatalf("unsafe ticket runtime defaults: %+v", cfg)
	}
	if cfg.TicketExportReconcileBatch != 25 || cfg.TicketExportReconcileAttempts != 10 ||
		cfg.TicketExportReconcileTimeout != 5*time.Second ||
		cfg.TicketExportReconcileLease != 2*time.Minute ||
		cfg.TicketExportReconcileSafety != 15*time.Second ||
		cfg.TicketExportReconcileRetry != 15*time.Second ||
		cfg.TicketExportReconcileRetryMax != 15*time.Minute {
		t.Fatalf("unsafe ticket export reconciliation defaults: %+v", cfg)
	}
	if cfg.SLABatchSize != 10 || cfg.SLAOperationTimeout != 5*time.Second ||
		cfg.SLALeaseDuration != 2*time.Minute || cfg.SLARunTimeout != 2*time.Minute ||
		cfg.SLAMaximumAttempts != 10 || cfg.SLARetryBaseDelay != 15*time.Second ||
		cfg.SLARetryMaximumDelay != 15*time.Minute || cfg.SLAPollInterval != 2*time.Second {
		t.Fatalf("unsafe SLA worker defaults: %+v", cfg)
	}
	if cfg.SLAActionBatchSize != 10 || cfg.SLAActionQueueLimit != 100 ||
		cfg.SLAActionOperationTimeout != 5*time.Second || cfg.SLAActionLeaseDuration != 2*time.Minute ||
		cfg.SLAActionLeaseSafety != 15*time.Second || cfg.SLAActionRunTimeout != 2*time.Minute ||
		cfg.SLAActionPollInterval != 2*time.Second {
		t.Fatalf("unsafe SLA action worker defaults: %+v", cfg)
	}
	if cfg.SLAEventBatchSize != 10 || cfg.SLAEventOperationTimeout != 5*time.Second ||
		cfg.SLAEventLeaseDuration != 2*time.Minute || cfg.SLAEventRunTimeout != 2*time.Minute ||
		cfg.SLAEventMaximumAttempts != 10 || cfg.SLAEventRetryBaseDelay != 15*time.Second ||
		cfg.SLAEventRetryMaximumDelay != 15*time.Minute || cfg.SLAEventPollInterval != 2*time.Second {
		t.Fatalf("unsafe SLA event ingress defaults: %+v", cfg)
	}
	if cfg.LDAPMaxConcurrent != 8 || cfg.LDAPSyncAbsenceBatch != 100 ||
		cfg.LDAPSyncLease != 30*time.Second || cfg.LDAPSyncMinBackoff != time.Second ||
		cfg.LDAPSyncMaxBackoff != 30*time.Second || cfg.LDAPSyncOperationTimeout != 30*time.Minute ||
		cfg.LDAPSyncParallelism != 2 || len(cfg.LDAPPrivateEgressCIDRs) != 0 ||
		len(cfg.LDAPAllowedStartTLSPorts) != 0 || len(cfg.LDAPAllowedLDAPSPorts) != 0 {
		t.Fatalf("unsafe LDAP sync defaults: %+v", cfg)
	}
}

func TestLoadRejectsOIDCOperationBudgetOutsideNominalLease(t *testing.T) {
	setDevelopmentIdentityKeyring(t)
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_DATABASE_TIMEOUT", "5s")
	t.Setenv("PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", "1m")
	t.Setenv("PERIAPSIS_OIDC_MAINTENANCE_LEASE_SAFETY", "59s")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted OIDC budgets that leave no time for the bounded claim read")
	}
}

func TestLoadRejectsUnsafeDFIRCleanupBatchAndLeaseBoundary(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"batch exceeds concurrent worker bound": {
			"PERIAPSIS_DFIR_CLEANUP_BATCH_SIZE": "17",
		},
		"delete plus safety equals lease": {
			"PERIAPSIS_DFIR_CLEANUP_DELETE_TIMEOUT": "25s",
			"PERIAPSIS_DFIR_CLEANUP_LEASE_DURATION": "30s",
		},
	} {
		t.Run(name, func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			for key, value := range values {
				t.Setenv(key, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted unsafe DFIR cleanup configuration")
			}
		})
	}
}

func TestLoadAcceptsBoundedTicketRuntimeConfiguration(t *testing.T) {
	setDevelopmentIdentityKeyring(t)
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_TICKET_RUNTIME_SERVICE_ACCOUNT_ID", "01890f00-0000-7000-8000-000000000001")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_SPOOL_DIR", filepath.Clean(t.TempDir()))
	t.Setenv("PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER", "123456789012")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.TicketRuntimeServiceAccountID.String() != "01890f00-0000-7000-8000-000000000001" ||
		cfg.TicketExportExpectedOwner != "123456789012" ||
		cfg.TicketExportSpoolDirectory != filepath.Clean(os.Getenv("PERIAPSIS_TICKET_EXPORT_SPOOL_DIR")) {
		t.Fatalf("ticket runtime configuration = %+v", cfg)
	}
}

func TestLoadRejectsInvalidTicketRuntimeConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "PERIAPSIS_TICKET_RUNTIME_SERVICE_ACCOUNT_ID", value: "01890f00-0000-4000-8000-000000000001"},
		{name: "PERIAPSIS_TICKET_EXPORT_SPOOL_DIR", value: "relative/spool"},
		{name: "PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER", value: "1234"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			t.Setenv(test.name, test.value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %s=%q", test.name, test.value)
			}
		})
	}
}

func TestLoadAcceptsBoundedWorkerMaintenanceSettings(t *testing.T) {
	setDevelopmentIdentityKeyring(t)
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_AUTH_CLEANUP_BATCH_SIZE", "1000")
	t.Setenv("PERIAPSIS_AUTH_CLEANUP_INTERVAL", "1m")
	t.Setenv("PERIAPSIS_DATABASE_TIMEOUT", "25s")
	t.Setenv("PERIAPSIS_WORKER_POLL_INTERVAL", "1m")
	t.Setenv("PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS", "10.20.0.0/16,fd20::/16")
	t.Setenv("PERIAPSIS_FEDERATED_HTTPS_PORTS", "8443,9443")
	t.Setenv("PERIAPSIS_FEDERATED_MAX_CONCURRENT", "256")
	t.Setenv("PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", "1m")
	t.Setenv("PERIAPSIS_FEDERATED_CA_BUNDLE_FILE", " C:\\trust\\federated-ca.pem ")
	t.Setenv("PERIAPSIS_OIDC_MAINTENANCE_BATCH_SIZE", "90")
	t.Setenv("PERIAPSIS_OIDC_MAINTENANCE_LEASE_SAFETY", "34s")
	t.Setenv("PERIAPSIS_OIDC_MAINTENANCE_POLL_INTERVAL", "100ms")
	t.Setenv("PERIAPSIS_SLA_BATCH_SIZE", "100")
	t.Setenv("PERIAPSIS_SLA_OPERATION_TIMEOUT", "1s")
	t.Setenv("PERIAPSIS_SLA_LEASE_DURATION", "5m")
	t.Setenv("PERIAPSIS_SLA_RUN_TIMEOUT", "5m")
	t.Setenv("PERIAPSIS_SLA_MAXIMUM_ATTEMPTS", "100")
	t.Setenv("PERIAPSIS_SLA_RETRY_BASE_DELAY", "1h")
	t.Setenv("PERIAPSIS_SLA_RETRY_MAXIMUM_DELAY", "24h")
	t.Setenv("PERIAPSIS_SLA_POLL_INTERVAL", "1m")
	t.Setenv("PERIAPSIS_SLA_ACTION_BATCH_SIZE", "100")
	t.Setenv("PERIAPSIS_SLA_ACTION_QUEUE_LIMIT", "500")
	t.Setenv("PERIAPSIS_SLA_ACTION_OPERATION_TIMEOUT", "2m")
	t.Setenv("PERIAPSIS_SLA_ACTION_LEASE_DURATION", "15m")
	t.Setenv("PERIAPSIS_SLA_ACTION_LEASE_SAFETY", "1m")
	t.Setenv("PERIAPSIS_SLA_ACTION_RUN_TIMEOUT", "15m")
	t.Setenv("PERIAPSIS_SLA_ACTION_POLL_INTERVAL", "1m")
	t.Setenv("PERIAPSIS_SLA_EVENT_BATCH_SIZE", "100")
	t.Setenv("PERIAPSIS_SLA_EVENT_OPERATION_TIMEOUT", "1s")
	t.Setenv("PERIAPSIS_SLA_EVENT_LEASE_DURATION", "5m")
	t.Setenv("PERIAPSIS_SLA_EVENT_RUN_TIMEOUT", "5m")
	t.Setenv("PERIAPSIS_SLA_EVENT_MAXIMUM_ATTEMPTS", "12")
	t.Setenv("PERIAPSIS_SLA_EVENT_RETRY_BASE_DELAY", "1h")
	t.Setenv("PERIAPSIS_SLA_EVENT_RETRY_MAXIMUM_DELAY", "24h")
	t.Setenv("PERIAPSIS_SLA_EVENT_POLL_INTERVAL", "1m")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_RECONCILE_BATCH_SIZE", "100")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_RECONCILE_MAXIMUM_ATTEMPTS", "100")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_RECONCILE_OPERATION_TIMEOUT", "5m")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_DURATION", "15m")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_SAFETY", "1m")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_BASE_DELAY", "24h")
	t.Setenv("PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_MAXIMUM_DELAY", "24h")
	t.Setenv("PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS", "10.10.0.0/16,fd00::/8")
	t.Setenv("PERIAPSIS_LDAP_STARTTLS_PORTS", "1389,2389")
	t.Setenv("PERIAPSIS_LDAP_LDAPS_PORTS", "1636")
	t.Setenv("PERIAPSIS_LDAP_MAX_CONCURRENT", "256")
	t.Setenv("PERIAPSIS_LDAP_SYNC_ABSENCE_BATCH_SIZE", "200")
	t.Setenv("PERIAPSIS_LDAP_SYNC_LEASE", "10m")
	t.Setenv("PERIAPSIS_LDAP_SYNC_MIN_BACKOFF", "1m")
	t.Setenv("PERIAPSIS_LDAP_SYNC_MAX_BACKOFF", "5m")
	t.Setenv("PERIAPSIS_LDAP_SYNC_OPERATION_TIMEOUT", "2h")
	t.Setenv("PERIAPSIS_LDAP_SYNC_PARALLELISM", "16")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AuthCleanupBatch != 1000 || cfg.AuthCleanupInterval != time.Minute ||
		cfg.DatabaseTimeout != 25*time.Second || cfg.PollInterval != time.Minute {
		t.Fatalf("unexpected bounded worker settings: %+v", cfg)
	}
	wantFederatedCIDRs := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd20::/16")}
	if !reflect.DeepEqual(cfg.FederatedPrivateEgressCIDRs, wantFederatedCIDRs) ||
		!reflect.DeepEqual(cfg.FederatedAllowedHTTPSPorts, []uint16{8443, 9443}) ||
		cfg.FederatedMaxConcurrent != 256 || cfg.FederatedOperationTimeout != time.Minute ||
		cfg.FederatedCABundleFile != "C:\\trust\\federated-ca.pem" || cfg.OIDCMaintenanceBatchSize != 90 ||
		cfg.OIDCMaintenanceLeaseSafety != 34*time.Second || cfg.OIDCMaintenancePollInterval != 100*time.Millisecond {
		t.Fatalf("unexpected bounded OIDC maintenance settings: %+v", cfg)
	}
	if cfg.SLABatchSize != 100 || cfg.SLAOperationTimeout != time.Second ||
		cfg.SLALeaseDuration != 5*time.Minute || cfg.SLARunTimeout != 5*time.Minute ||
		cfg.SLAMaximumAttempts != 100 || cfg.SLARetryBaseDelay != time.Hour ||
		cfg.SLARetryMaximumDelay != 24*time.Hour || cfg.SLAPollInterval != time.Minute {
		t.Fatalf("unexpected bounded SLA settings: %+v", cfg)
	}
	if cfg.SLAActionBatchSize != 100 || cfg.SLAActionQueueLimit != 500 ||
		cfg.SLAActionOperationTimeout != 2*time.Minute || cfg.SLAActionLeaseDuration != 15*time.Minute ||
		cfg.SLAActionLeaseSafety != time.Minute || cfg.SLAActionRunTimeout != 15*time.Minute ||
		cfg.SLAActionPollInterval != time.Minute {
		t.Fatalf("unexpected bounded SLA action settings: %+v", cfg)
	}
	if cfg.SLAEventBatchSize != 100 || cfg.SLAEventOperationTimeout != time.Second ||
		cfg.SLAEventLeaseDuration != 5*time.Minute || cfg.SLAEventRunTimeout != 5*time.Minute ||
		cfg.SLAEventMaximumAttempts != 12 || cfg.SLAEventRetryBaseDelay != time.Hour ||
		cfg.SLAEventRetryMaximumDelay != 24*time.Hour || cfg.SLAEventPollInterval != time.Minute {
		t.Fatalf("unexpected bounded SLA event ingress settings: %+v", cfg)
	}
	if cfg.TicketExportReconcileBatch != 100 || cfg.TicketExportReconcileAttempts != 100 ||
		cfg.TicketExportReconcileTimeout != 5*time.Minute ||
		cfg.TicketExportReconcileLease != 15*time.Minute ||
		cfg.TicketExportReconcileSafety != time.Minute ||
		cfg.TicketExportReconcileRetry != 24*time.Hour ||
		cfg.TicketExportReconcileRetryMax != 24*time.Hour {
		t.Fatalf("unexpected bounded ticket export reconciliation settings: %+v", cfg)
	}
	wantCIDRs := []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16"), netip.MustParsePrefix("fd00::/8")}
	if cfg.LDAPMaxConcurrent != 256 || cfg.LDAPSyncAbsenceBatch != 200 ||
		cfg.LDAPSyncLease != 10*time.Minute || cfg.LDAPSyncMinBackoff != time.Minute ||
		cfg.LDAPSyncMaxBackoff != 5*time.Minute || cfg.LDAPSyncOperationTimeout != 2*time.Hour ||
		cfg.LDAPSyncParallelism != 16 || len(cfg.LDAPPrivateEgressCIDRs) != len(wantCIDRs) ||
		cfg.LDAPPrivateEgressCIDRs[0] != wantCIDRs[0] || cfg.LDAPPrivateEgressCIDRs[1] != wantCIDRs[1] ||
		len(cfg.LDAPAllowedStartTLSPorts) != 2 || cfg.LDAPAllowedStartTLSPorts[0] != 1389 ||
		cfg.LDAPAllowedStartTLSPorts[1] != 2389 || len(cfg.LDAPAllowedLDAPSPorts) != 1 ||
		cfg.LDAPAllowedLDAPSPorts[0] != 1636 {
		t.Fatalf("unexpected bounded LDAP sync settings: %+v", cfg)
	}
}

func TestLoadRejectsUnsafeWorkerMaintenanceSettings(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "PERIAPSIS_AUTH_CLEANUP_BATCH_SIZE", value: "1001"},
		{name: "PERIAPSIS_AUTH_CLEANUP_INTERVAL", value: "59s"},
		{name: "PERIAPSIS_DATABASE_TIMEOUT", value: "26s"},
		{name: "PERIAPSIS_WORKER_POLL_INTERVAL", value: "999ms"},
		{name: "PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS", value: "10.0.0.1/8"},
		{name: "PERIAPSIS_FEDERATED_HTTPS_PORTS", value: "0443"},
		{name: "PERIAPSIS_FEDERATED_MAX_CONCURRENT", value: "257"},
		{name: "PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", value: "99ms"},
		{name: "PERIAPSIS_OIDC_MAINTENANCE_BATCH_SIZE", value: "2"},
		{name: "PERIAPSIS_OIDC_MAINTENANCE_LEASE_SAFETY", value: "999ms"},
		{name: "PERIAPSIS_OIDC_MAINTENANCE_POLL_INTERVAL", value: "99ms"},
		{name: "PERIAPSIS_SLA_BATCH_SIZE", value: "101"},
		{name: "PERIAPSIS_SLA_OPERATION_TIMEOUT", value: "121s"},
		{name: "PERIAPSIS_SLA_LEASE_DURATION", value: "9s"},
		{name: "PERIAPSIS_SLA_RUN_TIMEOUT", value: "5m1s"},
		{name: "PERIAPSIS_SLA_MAXIMUM_ATTEMPTS", value: "101"},
		{name: "PERIAPSIS_SLA_RETRY_BASE_DELAY", value: "3601s"},
		{name: "PERIAPSIS_SLA_RETRY_MAXIMUM_DELAY", value: "24h1s"},
		{name: "PERIAPSIS_SLA_POLL_INTERVAL", value: "999ms"},
		{name: "PERIAPSIS_SLA_ACTION_BATCH_SIZE", value: "101"},
		{name: "PERIAPSIS_SLA_ACTION_QUEUE_LIMIT", value: "501"},
		{name: "PERIAPSIS_SLA_ACTION_OPERATION_TIMEOUT", value: "121s"},
		{name: "PERIAPSIS_SLA_ACTION_LEASE_DURATION", value: "29s"},
		{name: "PERIAPSIS_SLA_ACTION_LEASE_SAFETY", value: "61s"},
		{name: "PERIAPSIS_SLA_ACTION_RUN_TIMEOUT", value: "15m1s"},
		{name: "PERIAPSIS_SLA_ACTION_POLL_INTERVAL", value: "999ms"},
		{name: "PERIAPSIS_SLA_EVENT_BATCH_SIZE", value: "101"},
		{name: "PERIAPSIS_SLA_EVENT_OPERATION_TIMEOUT", value: "121s"},
		{name: "PERIAPSIS_SLA_EVENT_LEASE_DURATION", value: "9s"},
		{name: "PERIAPSIS_SLA_EVENT_RUN_TIMEOUT", value: "15m1s"},
		{name: "PERIAPSIS_SLA_EVENT_MAXIMUM_ATTEMPTS", value: "13"},
		{name: "PERIAPSIS_SLA_EVENT_RETRY_BASE_DELAY", value: "3601s"},
		{name: "PERIAPSIS_SLA_EVENT_RETRY_MAXIMUM_DELAY", value: "24h1s"},
		{name: "PERIAPSIS_SLA_EVENT_POLL_INTERVAL", value: "999ms"},
		{name: "PERIAPSIS_TICKET_EXPORT_RECONCILE_BATCH_SIZE", value: "101"},
		{name: "PERIAPSIS_TICKET_EXPORT_RECONCILE_MAXIMUM_ATTEMPTS", value: "101"},
		{name: "PERIAPSIS_TICKET_EXPORT_RECONCILE_OPERATION_TIMEOUT", value: "5m1s"},
		{name: "PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_DURATION", value: "29s"},
		{name: "PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_SAFETY", value: "61s"},
		{name: "PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_BASE_DELAY", value: "24h1s"},
		{name: "PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_MAXIMUM_DELAY", value: "24h1s"},
		{name: "PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS", value: "10.0.0.1/8"},
		{name: "PERIAPSIS_LDAP_STARTTLS_PORTS", value: "0389"},
		{name: "PERIAPSIS_LDAP_LDAPS_PORTS", value: "0"},
		{name: "PERIAPSIS_LDAP_MAX_CONCURRENT", value: "257"},
		{name: "PERIAPSIS_LDAP_SYNC_ABSENCE_BATCH_SIZE", value: "201"},
		{name: "PERIAPSIS_LDAP_SYNC_LEASE", value: "999ms"},
		{name: "PERIAPSIS_LDAP_SYNC_MIN_BACKOFF", value: "99ms"},
		{name: "PERIAPSIS_LDAP_SYNC_MAX_BACKOFF", value: "6m"},
		{name: "PERIAPSIS_LDAP_SYNC_OPERATION_TIMEOUT", value: "59s"},
		{name: "PERIAPSIS_LDAP_SYNC_PARALLELISM", value: "17"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			t.Setenv(test.name, test.value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %s=%q", test.name, test.value)
			}
		})
	}
}

func TestLoadRejectsSubMicrosecondOIDCMaintenanceDurations(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "PERIAPSIS_DATABASE_TIMEOUT", value: "1s1ns"},
		{name: "PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", value: "100ms1ns"},
		{name: "PERIAPSIS_OIDC_MAINTENANCE_LEASE_SAFETY", value: "1s1ns"},
		{name: "PERIAPSIS_OIDC_MAINTENANCE_POLL_INTERVAL", value: "100ms1ns"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			t.Setenv(test.name, test.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), test.name) ||
				!strings.Contains(err.Error(), "must use whole microseconds") {
				t.Fatalf("Load() error = %v, want actionable microsecond error", err)
			}
		})
	}
}

func TestLoadRejectsLDAPSyncBackoffInversionAndDuplicatePolicyValues(t *testing.T) {
	tests := []map[string]string{
		{
			"PERIAPSIS_LDAP_SYNC_MIN_BACKOFF": "10s",
			"PERIAPSIS_LDAP_SYNC_MAX_BACKOFF": "9s",
		},
		{"PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS": "10.0.0.0/8,10.0.0.0/8"},
		{"PERIAPSIS_LDAP_STARTTLS_PORTS": "1389,1389"},
		{"PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS": "10.0.0.0/8,10.0.0.0/8"},
		{"PERIAPSIS_FEDERATED_HTTPS_PORTS": "8443,8443"},
	}
	for index, environment := range tests {
		t.Run(string(rune('A'+index)), func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			for name, value := range environment {
				t.Setenv(name, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted an ambiguous LDAP sync policy")
			}
		})
	}
}

func TestLoadRejectsUnsafeSLATimingRelationships(t *testing.T) {
	tests := []map[string]string{
		{
			"PERIAPSIS_SLA_BATCH_SIZE":        "100",
			"PERIAPSIS_SLA_OPERATION_TIMEOUT": "2s",
		},
		{
			"PERIAPSIS_SLA_LEASE_DURATION": "112s",
			"PERIAPSIS_SLA_RUN_TIMEOUT":    "112s",
		},
		{
			"PERIAPSIS_SLA_RETRY_BASE_DELAY":    "10m",
			"PERIAPSIS_SLA_RETRY_MAXIMUM_DELAY": "9m",
		},
		{
			"PERIAPSIS_SLA_LEASE_DURATION": "2m",
			"PERIAPSIS_SLA_RUN_TIMEOUT":    "3m",
		},
	}
	for index, environment := range tests {
		t.Run(string(rune('A'+index)), func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			for name, value := range environment {
				t.Setenv(name, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted unsafe SLA timing relationships")
			}
		})
	}
}

func TestLoadRejectsUnsafeSLAActionTimingRelationships(t *testing.T) {
	tests := []map[string]string{
		{
			"PERIAPSIS_SLA_ACTION_OPERATION_TIMEOUT": "30s",
			"PERIAPSIS_SLA_ACTION_LEASE_DURATION":    "30s",
			"PERIAPSIS_SLA_ACTION_LEASE_SAFETY":      "1s",
		},
		{
			"PERIAPSIS_SLA_ACTION_OPERATION_TIMEOUT": "20s",
			"PERIAPSIS_SLA_ACTION_RUN_TIMEOUT":       "10s",
		},
	}
	for index, environment := range tests {
		t.Run(string(rune('A'+index)), func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			for name, value := range environment {
				t.Setenv(name, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted unsafe SLA action timing relationships")
			}
		})
	}
}

func TestLoadRejectsUnsafeSLAEventIngressTimingRelationships(t *testing.T) {
	tests := []map[string]string{
		{
			"PERIAPSIS_SLA_EVENT_BATCH_SIZE":        "100",
			"PERIAPSIS_SLA_EVENT_OPERATION_TIMEOUT": "2s",
		},
		{
			"PERIAPSIS_SLA_EVENT_LEASE_DURATION": "119s",
			"PERIAPSIS_SLA_EVENT_RUN_TIMEOUT":    "119s",
		},
		{
			"PERIAPSIS_SLA_EVENT_RETRY_BASE_DELAY":    "10m",
			"PERIAPSIS_SLA_EVENT_RETRY_MAXIMUM_DELAY": "9m",
		},
		{
			"PERIAPSIS_SLA_EVENT_LEASE_DURATION": "2m",
			"PERIAPSIS_SLA_EVENT_RUN_TIMEOUT":    "3m",
		},
	}
	for index, environment := range tests {
		t.Run(string(rune('A'+index)), func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			for name, value := range environment {
				t.Setenv(name, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted unsafe SLA event ingress timing relationships")
			}
		})
	}
}

func TestLoadRejectsUnsafeTicketExportReconciliationTimingRelationships(t *testing.T) {
	tests := []map[string]string{
		{
			"PERIAPSIS_TICKET_EXPORT_RECONCILE_OPERATION_TIMEOUT": "30s",
			"PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_DURATION":    "30s",
			"PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_SAFETY":      "1s",
		},
		{
			"PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_BASE_DELAY":    "10m",
			"PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_MAXIMUM_DELAY": "9m",
		},
	}
	for index, environment := range tests {
		t.Run(string(rune('A'+index)), func(t *testing.T) {
			setDevelopmentIdentityKeyring(t)
			t.Setenv("PERIAPSIS_ENV", "development")
			for name, value := range environment {
				t.Setenv(name, value)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted unsafe ticket export reconciliation timing relationships")
			}
		})
	}
}

func TestLoadRejectsNonCanonicalEnvironment(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "Production")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a noncanonical environment")
	}
}

func TestLoadRejectsDirectDatabaseURLInProduction(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	t.Setenv("PERIAPSIS_DATABASE_URL", "postgres://example.invalid/periapsis")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an environment-only production database secret")
	}
}

func TestLoadDefaultsToProductionSafetyWhenEnvironmentIsMissing(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "")
	t.Setenv("PERIAPSIS_DATABASE_URL", "postgres://example.invalid/periapsis")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() failed open when PERIAPSIS_ENV was missing")
	}
}

func TestLoadRejectsDirectDatabaseURLAlongsideProductionSecretFile(t *testing.T) {
	databaseURLFile := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(databaseURLFile, []byte("postgres://file.example.invalid/periapsis"), 0o600); err != nil {
		t.Fatalf("write database URL fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_ENV", "production")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", databaseURLFile)
	t.Setenv("PERIAPSIS_DATABASE_URL", "postgres://stale.example.invalid/periapsis")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a direct database secret alongside its production secret file")
	}
}

func TestLoadReadsProductionDatabaseURLFromFile(t *testing.T) {
	databaseURLFile := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(databaseURLFile, []byte("postgres://example.invalid/periapsis"), 0o600); err != nil {
		t.Fatalf("write database URL fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_ENV", "production")
	identityKeyringFile := filepath.Join(t.TempDir(), "identity-keyring")
	if err := os.WriteFile(identityKeyringFile, []byte(validIdentityKeyring), 0o600); err != nil {
		t.Fatalf("write identity keyring fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING_FILE", identityKeyringFile)
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING", "")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", databaseURLFile)
	t.Setenv("PERIAPSIS_DATABASE_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://example.invalid/periapsis" {
		t.Fatalf("DatabaseURL = %q", cfg.DatabaseURL)
	}
}

func TestLoadRejectsMissingDevelopmentIdentityKeyring(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING", "")
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a missing identity keyring")
	}
}

func TestLoadRejectsDirectIdentityKeyringInProduction(t *testing.T) {
	databaseURLFile := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(databaseURLFile, []byte("postgres://example.invalid/periapsis"), 0o600); err != nil {
		t.Fatalf("write database URL fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_ENV", "production")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", databaseURLFile)
	t.Setenv("PERIAPSIS_DATABASE_URL", "")
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING", validIdentityKeyring)
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an environment-only production identity keyring")
	}
}
