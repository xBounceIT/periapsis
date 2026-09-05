// Package config loads worker runtime configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/worker/internal/dfircleanup"
	"github.com/periapsis-im/periapsis/services/worker/internal/oidcmaintenance"
)

// Config contains worker process settings.
type Config struct {
	Address                       string
	AuditOperationsEnabled        bool
	AuditRetentionSigningKeyFile  string
	AuditRetentionSigningKeyID    string
	AuditOperationsSpoolDirectory string
	AuthCleanupBatch              int
	AuthCleanupInterval           time.Duration
	DatabaseTimeout               time.Duration
	DatabaseURL                   string
	DFIRCleanupBatchSize          int
	DFIRCleanupDeleteTimeout      time.Duration
	DFIRCleanupLeaseDuration      time.Duration
	DFIRCleanupPollInterval       time.Duration
	DFIRCleanupRetryBaseDelay     time.Duration
	DFIRMaximumObjectBytes        int64
	DFIRScanBatchSize             int
	DFIRScanLeaseDuration         time.Duration
	DFIRScanOperationTimeout      time.Duration
	DFIRScanPollInterval          time.Duration
	DFIRScanRetryBaseDelay        time.Duration
	DFIRScanRetryMaximumDelay     time.Duration
	DFIRScanUploadPollDelay       time.Duration
	Environment                   string
	FederatedAllowedHTTPSPorts    []uint16
	FederatedCABundleFile         string
	FederatedMaxConcurrent        int
	FederatedOperationTimeout     time.Duration
	FederatedPrivateEgressCIDRs   []netip.Prefix
	IdentityKeyring               identity.Keyring
	LDAPAllowedLDAPSPorts         []uint16
	LDAPAllowedStartTLSPorts      []uint16
	LDAPMaxConcurrent             int
	LDAPPrivateEgressCIDRs        []netip.Prefix
	LDAPSyncAbsenceBatch          int
	LDAPSyncLease                 time.Duration
	LDAPSyncMaxBackoff            time.Duration
	LDAPSyncMinBackoff            time.Duration
	LDAPSyncOperationTimeout      time.Duration
	LDAPSyncParallelism           int
	OIDCMaintenanceBatchSize      int
	OIDCMaintenanceLeaseSafety    time.Duration
	OIDCMaintenancePollInterval   time.Duration
	PollInterval                  time.Duration
	Release                       string
	SLABatchSize                  int
	SLAActionBatchSize            int
	SLAActionLeaseDuration        time.Duration
	SLAActionLeaseSafety          time.Duration
	SLAActionOperationTimeout     time.Duration
	SLAActionPollInterval         time.Duration
	SLAActionQueueLimit           int
	SLAActionRunTimeout           time.Duration
	SLAEventBatchSize             int
	SLAEventLeaseDuration         time.Duration
	SLAEventMaximumAttempts       int
	SLAEventOperationTimeout      time.Duration
	SLAEventPollInterval          time.Duration
	SLAEventRetryBaseDelay        time.Duration
	SLAEventRetryMaximumDelay     time.Duration
	SLAEventRunTimeout            time.Duration
	SLALeaseDuration              time.Duration
	SLAMaximumAttempts            int
	SLAOperationTimeout           time.Duration
	SLAPollInterval               time.Duration
	SLARetryBaseDelay             time.Duration
	SLARetryMaximumDelay          time.Duration
	SLARunTimeout                 time.Duration
	TicketExportExpectedOwner     string
	TicketExportReconcileBatch    int
	TicketExportReconcileLease    time.Duration
	TicketExportReconcileSafety   time.Duration
	TicketExportReconcileTimeout  time.Duration
	TicketExportReconcileAttempts int
	TicketExportReconcileRetry    time.Duration
	TicketExportReconcileRetryMax time.Duration
	TicketExportSpoolDirectory    string
	TicketRuntimeServiceAccountID uuid.UUID
}

// Load reads and validates environment-backed settings.
func Load() (Config, error) {
	identityKeyringDocument, err := secretBytesOrFile("PERIAPSIS_IDENTITY_KEYRING")
	if err != nil {
		return Config{}, err
	}
	identityKeyring, err := identity.ParseKeyringDocument(identityKeyringDocument)
	if err != nil {
		return Config{}, errors.New("PERIAPSIS_IDENTITY_KEYRING is invalid or missing")
	}
	databaseURL, err := valueOrFile("PERIAPSIS_DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	environment := valueOrDefault("PERIAPSIS_ENV", "production")
	if err := validateEnvironment(environment); err != nil {
		return Config{}, err
	}
	authCleanupBatch, err := integerInRange("PERIAPSIS_AUTH_CLEANUP_BATCH_SIZE", 250, 1, 1000)
	if err != nil {
		return Config{}, err
	}
	authCleanupInterval, err := durationInRange(
		"PERIAPSIS_AUTH_CLEANUP_INTERVAL", 5*time.Minute, time.Minute, 24*time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	databaseTimeout, err := microsecondDurationInRange(
		"PERIAPSIS_DATABASE_TIMEOUT", 5*time.Second, time.Second, 25*time.Second,
	)
	if err != nil {
		return Config{}, err
	}
	pollInterval, err := durationInRange(
		"PERIAPSIS_WORKER_POLL_INTERVAL", 5*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	federatedPrivateEgressCIDRs, err := parseCanonicalPrivateEgressCIDRs(
		"PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS",
		os.Getenv("PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS"),
	)
	if err != nil {
		return Config{}, err
	}
	federatedHTTPSPorts, err := parseLDAPAllowedPorts("PERIAPSIS_FEDERATED_HTTPS_PORTS")
	if err != nil {
		return Config{}, err
	}
	federatedMaxConcurrent, err := integerInRange("PERIAPSIS_FEDERATED_MAX_CONCURRENT", 16, 1, 256)
	if err != nil {
		return Config{}, err
	}
	federatedOperationTimeout, err := microsecondDurationInRange(
		"PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", 20*time.Second, 100*time.Millisecond, 2*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	oidcMaintenanceBatchSize, err := integerInRange(
		"PERIAPSIS_OIDC_MAINTENANCE_BATCH_SIZE", 12, 3, 90,
	)
	if err != nil {
		return Config{}, err
	}
	oidcMaintenanceLeaseSafety, err := microsecondDurationInRange(
		"PERIAPSIS_OIDC_MAINTENANCE_LEASE_SAFETY", 5*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	if databaseTimeout+federatedOperationTimeout+oidcMaintenanceLeaseSafety+
		oidcmaintenance.MinimumLeaseSchedulingMargin > oidcmaintenance.NominalLeaseDuration {
		return Config{}, errors.New("OIDC maintenance claim, operation, and safety budgets must fit inside the nominal lease")
	}
	oidcMaintenancePollInterval, err := microsecondDurationInRange(
		"PERIAPSIS_OIDC_MAINTENANCE_POLL_INTERVAL", 2*time.Second, 100*time.Millisecond, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaBatchSize, err := integerInRange("PERIAPSIS_SLA_BATCH_SIZE", 10, 1, 100)
	if err != nil {
		return Config{}, err
	}
	slaOperationTimeout, err := durationInRange(
		"PERIAPSIS_SLA_OPERATION_TIMEOUT", 5*time.Second, time.Second, 2*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaLeaseDuration, err := durationInRange(
		"PERIAPSIS_SLA_LEASE_DURATION", 2*time.Minute, 10*time.Second, 5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaRunTimeout, err := durationInRange(
		"PERIAPSIS_SLA_RUN_TIMEOUT", 2*time.Minute, 10*time.Second, 5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	// One claim, up to one evaluation plus one terminal write per job, and one
	// authoritative queue-observation query must all fit inside the same fenced
	// run and lease.
	minimumSLACycle := time.Duration(2*slaBatchSize+2)*slaOperationTimeout + 5*time.Second
	if slaLeaseDuration < minimumSLACycle || slaRunTimeout < minimumSLACycle {
		return Config{}, errors.New("SLA lease and run timeouts must cover the bounded sequential batch")
	}
	if slaRunTimeout > slaLeaseDuration {
		return Config{}, errors.New("PERIAPSIS_SLA_RUN_TIMEOUT must not exceed PERIAPSIS_SLA_LEASE_DURATION")
	}
	slaMaximumAttempts, err := integerInRange("PERIAPSIS_SLA_MAXIMUM_ATTEMPTS", 10, 1, 100)
	if err != nil {
		return Config{}, err
	}
	slaRetryBaseDelay, err := durationInRange(
		"PERIAPSIS_SLA_RETRY_BASE_DELAY", 15*time.Second, time.Second, time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	slaRetryMaximumDelay, err := durationInRange(
		"PERIAPSIS_SLA_RETRY_MAXIMUM_DELAY", 15*time.Minute, time.Second, 24*time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	if slaRetryMaximumDelay < slaRetryBaseDelay {
		return Config{}, errors.New("PERIAPSIS_SLA_RETRY_MAXIMUM_DELAY must be at least PERIAPSIS_SLA_RETRY_BASE_DELAY")
	}
	slaPollInterval, err := durationInRange(
		"PERIAPSIS_SLA_POLL_INTERVAL", 2*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaActionBatchSize, err := integerInRange("PERIAPSIS_SLA_ACTION_BATCH_SIZE", 10, 1, 100)
	if err != nil {
		return Config{}, err
	}
	slaActionQueueLimit, err := integerInRange("PERIAPSIS_SLA_ACTION_QUEUE_LIMIT", 100, 1, 500)
	if err != nil {
		return Config{}, err
	}
	slaActionOperationTimeout, err := durationInRange(
		"PERIAPSIS_SLA_ACTION_OPERATION_TIMEOUT", 5*time.Second, time.Second, 2*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaActionLeaseDuration, err := durationInRange(
		"PERIAPSIS_SLA_ACTION_LEASE_DURATION", 2*time.Minute, 30*time.Second, 15*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaActionLeaseSafety, err := durationInRange(
		"PERIAPSIS_SLA_ACTION_LEASE_SAFETY", 15*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	if slaActionOperationTimeout+slaActionLeaseSafety > slaActionLeaseDuration {
		return Config{}, errors.New("SLA action operation timeout and safety must fit inside the lease")
	}
	slaActionRunTimeout, err := durationInRange(
		"PERIAPSIS_SLA_ACTION_RUN_TIMEOUT", 2*time.Minute, 10*time.Second, 15*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	if slaActionRunTimeout < slaActionOperationTimeout {
		return Config{}, errors.New("PERIAPSIS_SLA_ACTION_RUN_TIMEOUT must cover one operation")
	}
	slaActionPollInterval, err := durationInRange(
		"PERIAPSIS_SLA_ACTION_POLL_INTERVAL", 2*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaEventBatchSize, err := integerInRange("PERIAPSIS_SLA_EVENT_BATCH_SIZE", 10, 1, 100)
	if err != nil {
		return Config{}, err
	}
	slaEventOperationTimeout, err := durationInRange(
		"PERIAPSIS_SLA_EVENT_OPERATION_TIMEOUT", 5*time.Second, time.Second, 2*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaEventLeaseDuration, err := durationInRange(
		"PERIAPSIS_SLA_EVENT_LEASE_DURATION", 2*time.Minute, 10*time.Second, 15*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	slaEventRunTimeout, err := durationInRange(
		"PERIAPSIS_SLA_EVENT_RUN_TIMEOUT", 2*time.Minute, 10*time.Second, 15*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	// Readiness, one claim, up to one planning and one terminal transition per
	// event, and one authoritative observation share the same bounded run.
	minimumSLAEventCycle := time.Duration(2*slaEventBatchSize+3)*slaEventOperationTimeout + 5*time.Second
	if slaEventLeaseDuration < minimumSLAEventCycle || slaEventRunTimeout < minimumSLAEventCycle {
		return Config{}, errors.New("SLA event ingress lease and run timeouts must cover the bounded sequential batch")
	}
	if slaEventRunTimeout > slaEventLeaseDuration {
		return Config{}, errors.New("PERIAPSIS_SLA_EVENT_RUN_TIMEOUT must not exceed PERIAPSIS_SLA_EVENT_LEASE_DURATION")
	}
	// Source transactions persist a hard twelve-attempt ceiling so an abandoned
	// lease can always terminalize without consulting mutable worker settings.
	slaEventMaximumAttempts, err := integerInRange("PERIAPSIS_SLA_EVENT_MAXIMUM_ATTEMPTS", 10, 1, 12)
	if err != nil {
		return Config{}, err
	}
	slaEventRetryBaseDelay, err := durationInRange(
		"PERIAPSIS_SLA_EVENT_RETRY_BASE_DELAY", 15*time.Second, time.Second, time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	slaEventRetryMaximumDelay, err := durationInRange(
		"PERIAPSIS_SLA_EVENT_RETRY_MAXIMUM_DELAY", 15*time.Minute, time.Second, 24*time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	if slaEventRetryMaximumDelay < slaEventRetryBaseDelay {
		return Config{}, errors.New("PERIAPSIS_SLA_EVENT_RETRY_MAXIMUM_DELAY must be at least PERIAPSIS_SLA_EVENT_RETRY_BASE_DELAY")
	}
	slaEventPollInterval, err := durationInRange(
		"PERIAPSIS_SLA_EVENT_POLL_INTERVAL", 2*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	ticketExportReconcileBatch, err := integerInRange(
		"PERIAPSIS_TICKET_EXPORT_RECONCILE_BATCH_SIZE", 25, 1, 100,
	)
	if err != nil {
		return Config{}, err
	}
	ticketExportReconcileAttempts, err := integerInRange(
		"PERIAPSIS_TICKET_EXPORT_RECONCILE_MAXIMUM_ATTEMPTS", 10, 1, 100,
	)
	if err != nil {
		return Config{}, err
	}
	ticketExportReconcileTimeout, err := durationInRange(
		"PERIAPSIS_TICKET_EXPORT_RECONCILE_OPERATION_TIMEOUT", 5*time.Second,
		time.Second, 5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	ticketExportReconcileLease, err := durationInRange(
		"PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_DURATION", 2*time.Minute,
		30*time.Second, 15*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	ticketExportReconcileSafety, err := durationInRange(
		"PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_SAFETY", 15*time.Second,
		time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	if ticketExportReconcileTimeout+ticketExportReconcileSafety > ticketExportReconcileLease {
		return Config{}, errors.New("ticket export reconciliation operation timeout and safety must fit inside the lease")
	}
	ticketExportReconcileRetry, err := durationInRange(
		"PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_BASE_DELAY", 15*time.Second,
		time.Second, 24*time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	ticketExportReconcileRetryMax, err := durationInRange(
		"PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_MAXIMUM_DELAY", 15*time.Minute,
		time.Second, 24*time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	if ticketExportReconcileRetryMax < ticketExportReconcileRetry {
		return Config{}, errors.New("ticket export reconciliation retry maximum must be at least the base delay")
	}
	ldapPrivateEgressCIDRs, err := parseLDAPPrivateEgressCIDRs(
		os.Getenv("PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS"),
	)
	if err != nil {
		return Config{}, err
	}
	ldapStartTLSPorts, err := parseLDAPAllowedPorts("PERIAPSIS_LDAP_STARTTLS_PORTS")
	if err != nil {
		return Config{}, err
	}
	ldapPorts, err := parseLDAPAllowedPorts("PERIAPSIS_LDAP_LDAPS_PORTS")
	if err != nil {
		return Config{}, err
	}
	ldapMaxConcurrent, err := integerInRange("PERIAPSIS_LDAP_MAX_CONCURRENT", 8, 1, 256)
	if err != nil {
		return Config{}, err
	}
	ldapSyncAbsenceBatch, err := integerInRange("PERIAPSIS_LDAP_SYNC_ABSENCE_BATCH_SIZE", 100, 1, 200)
	if err != nil {
		return Config{}, err
	}
	ldapSyncLease, err := durationInRange(
		"PERIAPSIS_LDAP_SYNC_LEASE", 30*time.Second, time.Second, 10*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	ldapSyncMinBackoff, err := durationInRange(
		"PERIAPSIS_LDAP_SYNC_MIN_BACKOFF", time.Second, 100*time.Millisecond, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	ldapSyncMaxBackoff, err := durationInRange(
		"PERIAPSIS_LDAP_SYNC_MAX_BACKOFF", 30*time.Second, time.Second, 5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	if ldapSyncMaxBackoff < ldapSyncMinBackoff {
		return Config{}, errors.New("PERIAPSIS_LDAP_SYNC_MAX_BACKOFF must be at least PERIAPSIS_LDAP_SYNC_MIN_BACKOFF")
	}
	ldapSyncOperationTimeout, err := durationInRange(
		"PERIAPSIS_LDAP_SYNC_OPERATION_TIMEOUT", 30*time.Minute, time.Minute, 2*time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	ldapSyncParallelism, err := integerInRange("PERIAPSIS_LDAP_SYNC_PARALLELISM", 2, 1, 16)
	if err != nil {
		return Config{}, err
	}
	ticketRuntimeServiceAccount, err := valueOrFile("PERIAPSIS_TICKET_RUNTIME_SERVICE_ACCOUNT_ID")
	if err != nil {
		return Config{}, err
	}
	var ticketRuntimeServiceAccountID uuid.UUID
	if ticketRuntimeServiceAccount != "" {
		ticketRuntimeServiceAccountID, err = uuid.Parse(ticketRuntimeServiceAccount)
		if err != nil || ticketRuntimeServiceAccountID.Version() != 7 ||
			ticketRuntimeServiceAccountID.String() != ticketRuntimeServiceAccount {
			return Config{}, errors.New("PERIAPSIS_TICKET_RUNTIME_SERVICE_ACCOUNT_ID must be a canonical UUIDv7")
		}
	}
	ticketExportSpoolDirectory := strings.TrimSpace(os.Getenv("PERIAPSIS_TICKET_EXPORT_SPOOL_DIR"))
	if ticketExportSpoolDirectory == "" {
		ticketExportSpoolDirectory = filepath.Clean(os.TempDir())
	}
	if !filepath.IsAbs(ticketExportSpoolDirectory) || filepath.Clean(ticketExportSpoolDirectory) != ticketExportSpoolDirectory {
		return Config{}, errors.New("PERIAPSIS_TICKET_EXPORT_SPOOL_DIR must be an absolute clean path")
	}
	ticketExportExpectedOwner := strings.TrimSpace(os.Getenv("PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER"))
	if !validExpectedBucketOwner(ticketExportExpectedOwner) {
		return Config{}, errors.New("PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER must be a 12-digit account ID")
	}
	auditSigningKeyFile := strings.TrimSpace(os.Getenv("PERIAPSIS_AUDIT_RETENTION_SIGNING_KEY_FILE"))
	auditSigningKeyID := strings.TrimSpace(os.Getenv("PERIAPSIS_AUDIT_RETENTION_SIGNING_KEY_ID"))
	if (auditSigningKeyFile == "") != (auditSigningKeyID == "") {
		return Config{}, errors.New("audit retention signing key file and key ID must be configured together")
	}
	if auditSigningKeyFile != "" && (!filepath.IsAbs(auditSigningKeyFile) ||
		filepath.Clean(auditSigningKeyFile) != auditSigningKeyFile) {
		return Config{}, errors.New("PERIAPSIS_AUDIT_RETENTION_SIGNING_KEY_FILE must be an absolute clean path")
	}
	if auditSigningKeyID != "" && !validAuditSigningKeyID(auditSigningKeyID) {
		return Config{}, errors.New("PERIAPSIS_AUDIT_RETENTION_SIGNING_KEY_ID is invalid")
	}
	auditSpoolDirectory := strings.TrimSpace(os.Getenv("PERIAPSIS_AUDIT_OPERATIONS_SPOOL_DIR"))
	if auditSpoolDirectory == "" {
		auditSpoolDirectory = filepath.Clean(os.TempDir())
	}
	if !filepath.IsAbs(auditSpoolDirectory) || filepath.Clean(auditSpoolDirectory) != auditSpoolDirectory {
		return Config{}, errors.New("PERIAPSIS_AUDIT_OPERATIONS_SPOOL_DIR must be an absolute clean path")
	}
	dfirMaximumObjectBytes, err := int64InRange(
		"PERIAPSIS_DFIR_MAX_OBJECT_BYTES", 5_000_000_000, 1_024*1_024, 5_000_000_000,
	)
	if err != nil {
		return Config{}, err
	}
	dfirScanBatchSize, err := integerInRange("PERIAPSIS_DFIR_SCAN_BATCH_SIZE", 4, 1, 16)
	if err != nil {
		return Config{}, err
	}
	dfirScanLeaseDuration, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_SCAN_LEASE_DURATION", 10*time.Minute, 30*time.Second, 30*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	dfirScanOperationTimeout, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_SCAN_OPERATION_TIMEOUT", 6*time.Minute, 10*time.Second, 15*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	if dfirScanOperationTimeout+5*time.Second >= dfirScanLeaseDuration {
		return Config{}, errors.New("DFIR scan operation timeout and safety must fit inside the lease")
	}
	dfirScanUploadPollDelay, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_SCAN_UPLOAD_POLL_DELAY", 5*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	dfirScanRetryBaseDelay, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_SCAN_RETRY_BASE_DELAY", 15*time.Second, time.Second, time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	dfirScanRetryMaximumDelay, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_SCAN_RETRY_MAXIMUM_DELAY", 15*time.Minute, time.Second, 24*time.Hour,
	)
	if err != nil || dfirScanRetryMaximumDelay < dfirScanRetryBaseDelay {
		return Config{}, errors.New("DFIR scan retry maximum must be at least the base delay")
	}
	dfirScanPollInterval, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_SCAN_POLL_INTERVAL", 2*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	dfirCleanupBatchSize, err := integerInRange(
		"PERIAPSIS_DFIR_CLEANUP_BATCH_SIZE", 16, 1, dfircleanup.MaximumBatchSize,
	)
	if err != nil {
		return Config{}, err
	}
	dfirCleanupLeaseDuration, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_CLEANUP_LEASE_DURATION", 2*time.Minute, 30*time.Second, 15*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	dfirCleanupDeleteTimeout, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_CLEANUP_DELETE_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute,
	)
	if err != nil || dfirCleanupDeleteTimeout+5*time.Second >= dfirCleanupLeaseDuration {
		return Config{}, errors.New("DFIR cleanup delete timeout and safety must fit inside the lease")
	}
	dfirCleanupRetryBaseDelay, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_CLEANUP_RETRY_BASE_DELAY", 10*time.Second, time.Second, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	dfirCleanupPollInterval, err := microsecondDurationInRange(
		"PERIAPSIS_DFIR_CLEANUP_POLL_INTERVAL", 30*time.Second, time.Second, 5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Address:                       valueOrDefault("PERIAPSIS_WORKER_ADDR", ":8082"),
		AuditOperationsEnabled:        auditSigningKeyFile != "",
		AuditRetentionSigningKeyFile:  auditSigningKeyFile,
		AuditRetentionSigningKeyID:    auditSigningKeyID,
		AuditOperationsSpoolDirectory: auditSpoolDirectory,
		AuthCleanupBatch:              authCleanupBatch,
		AuthCleanupInterval:           authCleanupInterval,
		DatabaseTimeout:               databaseTimeout,
		DatabaseURL:                   databaseURL,
		DFIRCleanupBatchSize:          dfirCleanupBatchSize,
		DFIRCleanupDeleteTimeout:      dfirCleanupDeleteTimeout,
		DFIRCleanupLeaseDuration:      dfirCleanupLeaseDuration,
		DFIRCleanupPollInterval:       dfirCleanupPollInterval,
		DFIRCleanupRetryBaseDelay:     dfirCleanupRetryBaseDelay,
		DFIRMaximumObjectBytes:        dfirMaximumObjectBytes,
		DFIRScanBatchSize:             dfirScanBatchSize,
		DFIRScanLeaseDuration:         dfirScanLeaseDuration,
		DFIRScanOperationTimeout:      dfirScanOperationTimeout,
		DFIRScanPollInterval:          dfirScanPollInterval,
		DFIRScanRetryBaseDelay:        dfirScanRetryBaseDelay,
		DFIRScanRetryMaximumDelay:     dfirScanRetryMaximumDelay,
		DFIRScanUploadPollDelay:       dfirScanUploadPollDelay,
		Environment:                   environment,
		FederatedAllowedHTTPSPorts:    federatedHTTPSPorts,
		FederatedCABundleFile:         strings.TrimSpace(os.Getenv("PERIAPSIS_FEDERATED_CA_BUNDLE_FILE")),
		FederatedMaxConcurrent:        federatedMaxConcurrent,
		FederatedOperationTimeout:     federatedOperationTimeout,
		FederatedPrivateEgressCIDRs:   federatedPrivateEgressCIDRs,
		IdentityKeyring:               identityKeyring,
		LDAPAllowedLDAPSPorts:         ldapPorts,
		LDAPAllowedStartTLSPorts:      ldapStartTLSPorts,
		LDAPMaxConcurrent:             ldapMaxConcurrent,
		LDAPPrivateEgressCIDRs:        ldapPrivateEgressCIDRs,
		LDAPSyncAbsenceBatch:          ldapSyncAbsenceBatch,
		LDAPSyncLease:                 ldapSyncLease,
		LDAPSyncMaxBackoff:            ldapSyncMaxBackoff,
		LDAPSyncMinBackoff:            ldapSyncMinBackoff,
		LDAPSyncOperationTimeout:      ldapSyncOperationTimeout,
		LDAPSyncParallelism:           ldapSyncParallelism,
		OIDCMaintenanceBatchSize:      oidcMaintenanceBatchSize,
		OIDCMaintenanceLeaseSafety:    oidcMaintenanceLeaseSafety,
		OIDCMaintenancePollInterval:   oidcMaintenancePollInterval,
		PollInterval:                  pollInterval,
		Release:                       valueOrDefault("PERIAPSIS_RELEASE", "development"),
		SLABatchSize:                  slaBatchSize,
		SLAActionBatchSize:            slaActionBatchSize,
		SLAActionLeaseDuration:        slaActionLeaseDuration,
		SLAActionLeaseSafety:          slaActionLeaseSafety,
		SLAActionOperationTimeout:     slaActionOperationTimeout,
		SLAActionPollInterval:         slaActionPollInterval,
		SLAActionQueueLimit:           slaActionQueueLimit,
		SLAActionRunTimeout:           slaActionRunTimeout,
		SLAEventBatchSize:             slaEventBatchSize,
		SLAEventLeaseDuration:         slaEventLeaseDuration,
		SLAEventMaximumAttempts:       slaEventMaximumAttempts,
		SLAEventOperationTimeout:      slaEventOperationTimeout,
		SLAEventPollInterval:          slaEventPollInterval,
		SLAEventRetryBaseDelay:        slaEventRetryBaseDelay,
		SLAEventRetryMaximumDelay:     slaEventRetryMaximumDelay,
		SLAEventRunTimeout:            slaEventRunTimeout,
		TicketExportReconcileBatch:    ticketExportReconcileBatch,
		TicketExportReconcileLease:    ticketExportReconcileLease,
		TicketExportReconcileSafety:   ticketExportReconcileSafety,
		TicketExportReconcileTimeout:  ticketExportReconcileTimeout,
		TicketExportReconcileAttempts: ticketExportReconcileAttempts,
		TicketExportReconcileRetry:    ticketExportReconcileRetry,
		TicketExportReconcileRetryMax: ticketExportReconcileRetryMax,
		SLALeaseDuration:              slaLeaseDuration,
		SLAMaximumAttempts:            slaMaximumAttempts,
		SLAOperationTimeout:           slaOperationTimeout,
		SLAPollInterval:               slaPollInterval,
		SLARetryBaseDelay:             slaRetryBaseDelay,
		SLARetryMaximumDelay:          slaRetryMaximumDelay,
		SLARunTimeout:                 slaRunTimeout,
		TicketExportExpectedOwner:     ticketExportExpectedOwner,
		TicketExportSpoolDirectory:    ticketExportSpoolDirectory,
		TicketRuntimeServiceAccountID: ticketRuntimeServiceAccountID,
	}
	_, portText, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return Config{}, errors.New("PERIAPSIS_WORKER_ADDR must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1024 || port > 65535 {
		return Config{}, errors.New("PERIAPSIS_WORKER_ADDR must use a non-privileged TCP port")
	}
	if cfg.Environment == "production" {
		if strings.TrimSpace(os.Getenv("PERIAPSIS_DATABASE_URL")) != "" {
			return Config{}, errors.New("PERIAPSIS_DATABASE_URL must not be set in production; use PERIAPSIS_DATABASE_URL_FILE")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_DATABASE_URL_FILE")) == "" || cfg.DatabaseURL == "" {
			return Config{}, errors.New("PERIAPSIS_DATABASE_URL_FILE is required in production")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_IDENTITY_KEYRING")) != "" {
			return Config{}, errors.New("PERIAPSIS_IDENTITY_KEYRING must not be set in production; use PERIAPSIS_IDENTITY_KEYRING_FILE")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_IDENTITY_KEYRING_FILE")) == "" {
			return Config{}, errors.New("PERIAPSIS_IDENTITY_KEYRING_FILE is required in production")
		}
	}
	return cfg, nil
}

func validExpectedBucketOwner(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 12 {
		return false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func validAuditSigningKeyID(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' &&
		(value[0] < '0' || value[0] > '9') {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '.' || character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func parseLDAPPrivateEgressCIDRs(value string) ([]netip.Prefix, error) {
	return parseCanonicalPrivateEgressCIDRs("PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS", value)
}

func parseCanonicalPrivateEgressCIDRs(name, value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 64 {
		return nil, fmt.Errorf("%s must contain at most 64 entries", name)
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		canonical := strings.TrimSpace(part)
		prefix, err := netip.ParsePrefix(canonical)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
			prefix != prefix.Masked() || prefix.String() != canonical {
			return nil, fmt.Errorf("%s must be a comma-separated canonical CIDR list", name)
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, fmt.Errorf("%s must not contain duplicates", name)
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseLDAPAllowedPorts(name string) ([]uint16, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 16 {
		return nil, fmt.Errorf("%s must contain at most 16 ports", name)
	}
	ports := make([]uint16, 0, len(parts))
	seen := make(map[uint16]struct{}, len(parts))
	for _, part := range parts {
		canonical := strings.TrimSpace(part)
		parsed, err := strconv.ParseUint(canonical, 10, 16)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != canonical {
			return nil, fmt.Errorf("%s must be a comma-separated canonical port list", name)
		}
		port := uint16(parsed)
		if _, duplicate := seen[port]; duplicate {
			return nil, fmt.Errorf("%s must not contain duplicate ports", name)
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

func validateEnvironment(environment string) error {
	switch environment {
	case "development", "test", "production":
		return nil
	default:
		return errors.New("PERIAPSIS_ENV must be development, test, or production")
	}
}

func valueOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func integerInRange(name string, fallback, minimum, maximum int) (int, error) {
	raw := valueOrDefault(name, strconv.Itoa(fallback))
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func int64InRange(name string, fallback, minimum, maximum int64) (int64, error) {
	raw := valueOrDefault(name, strconv.FormatInt(fallback, 10))
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minimum || value > maximum || strconv.FormatInt(value, 10) != raw {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func durationInRange(name string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	raw := valueOrDefault(name, fallback.String())
	value, err := time.ParseDuration(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return value, nil
}

func microsecondDurationInRange(
	name string,
	fallback time.Duration,
	minimum time.Duration,
	maximum time.Duration,
) (time.Duration, error) {
	value, err := durationInRange(name, fallback, minimum, maximum)
	if err != nil {
		return 0, err
	}
	if value%time.Microsecond != 0 {
		return 0, fmt.Errorf("%s must use whole microseconds", name)
	}
	return value, nil
}

func valueOrFile(name string) (string, error) {
	fileName := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if fileName == "" {
		return strings.TrimSpace(os.Getenv(name)), nil
	}
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	value := strings.TrimSpace(string(contents))
	if value == "" {
		return "", fmt.Errorf("%s_FILE contains an empty value", name)
	}
	return value, nil
}

func secretBytesOrFile(name string) ([]byte, error) {
	fileName := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if fileName == "" {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return nil, nil
		}
		return []byte(value), nil
	}
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("read %s_FILE: %w", name, err)
	}
	trimmed := bytes.TrimSpace(contents)
	if len(trimmed) == 0 {
		clear(contents)
		return nil, fmt.Errorf("%s_FILE contains an empty value", name)
	}
	copy(contents, trimmed)
	clear(contents[len(trimmed):])
	return contents[:len(trimmed)], nil
}
