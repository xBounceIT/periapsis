package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/worker/internal/auditoperations"
	"github.com/periapsis-im/periapsis/services/worker/internal/config"
	customfieldimport "github.com/periapsis-im/periapsis/services/worker/internal/customfieldimport"
	"github.com/periapsis-im/periapsis/services/worker/internal/dfircleanup"
	"github.com/periapsis-im/periapsis/services/worker/internal/dfirscan"
	"github.com/periapsis-im/periapsis/services/worker/internal/identitysync"
	"github.com/periapsis-im/periapsis/services/worker/internal/oidcmaintenance"
	"github.com/periapsis-im/periapsis/services/worker/internal/postgres"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaaction"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaengine"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaevent"
	"github.com/periapsis-im/periapsis/services/worker/internal/telemetry"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketbulk"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketexport"
)

func main() {
	level, levelErr := parseLogLevel(os.Getenv("PERIAPSIS_LOG_LEVEL"))
	logger := slog.New(telemetry.NewTraceContextHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}),
	))
	if levelErr != nil {
		logger.Error("worker configuration invalid", "error", levelErr)
		os.Exit(1)
	}
	if err := run(logger); err != nil {
		logger.Error("worker stopped", "error", err)
		os.Exit(1)
	}
}

func parseLogLevel(value string) (slog.Level, error) {
	switch value {
	case "", "info":
		return slog.LevelInfo, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, errors.New("PERIAPSIS_LOG_LEVEL must be info or error")
	}
}

func runtimeMaximumAttempts(cfg config.Config) (uint16, uint16, error) {
	slaAttempts, eventAttempts := cfg.SLAMaximumAttempts, cfg.SLAEventMaximumAttempts
	if slaAttempts < 1 || slaAttempts > 100 {
		return 0, 0, errors.New("PERIAPSIS_SLA_MAXIMUM_ATTEMPTS must be between 1 and 100")
	}
	if eventAttempts < 1 || eventAttempts > 12 {
		return 0, 0, errors.New("PERIAPSIS_SLA_EVENT_MAXIMUM_ATTEMPTS must be between 1 and 12")
	}
	return uint16(slaAttempts), uint16(eventAttempts), nil
}

func run(logger *slog.Logger) (runErr error) {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slaMaximumAttempts, slaEventMaximumAttempts, err := runtimeMaximumAttempts(cfg)
	if err != nil {
		return err
	}
	identityReadiness, err := cfg.IdentityKeyring.ReadinessEvidence()
	if err != nil {
		return errors.New("prepare identity keyring readiness evidence")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	telemetryConfig, err := telemetry.LoadConfig(cfg.Environment, "periapsis-worker", cfg.Release)
	if err != nil {
		return err
	}
	telemetryRuntime, err := telemetry.Start(ctx, telemetryConfig, logger)
	if err != nil {
		return err
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		runErr = errors.Join(
			runErr,
			telemetryRuntime.ForceFlush(shutdownContext),
			telemetryRuntime.Shutdown(shutdownContext),
		)
	}()

	var ready workerReadiness
	metrics := &telemetry.Metrics{}
	var pool *pgxpool.Pool
	var background sync.WaitGroup
	if cfg.DatabaseURL != "" {
		poolConfig, err := databasePoolConfig(cfg.DatabaseURL, cfg.DatabaseTimeout, telemetryRuntime)
		if err != nil {
			return err
		}
		pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			return errors.New("create database pool")
		}
		defer pool.Close()
		validationContext, cancelValidation := context.WithTimeout(ctx, cfg.DatabaseTimeout)
		validationErr := postgres.ValidateRuntimeDatabaseRole(validationContext, pool)
		cancelValidation()
		if validationErr != nil {
			return validationErr
		}
		oidcUpstream, err := oidcmaintenance.NewUpstream(oidcmaintenance.UpstreamOptions{
			Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
			PrivateEgressCIDRs: cfg.FederatedPrivateEgressCIDRs,
			AllowedHTTPSPorts:  cfg.FederatedAllowedHTTPSPorts,
			CABundleFile:       cfg.FederatedCABundleFile,
			OperationTimeout:   cfg.FederatedOperationTimeout,
			MaxConcurrent:      cfg.FederatedMaxConcurrent,
		})
		if err != nil {
			return errors.New("configure OIDC maintenance egress")
		}
		oidcMaintenanceWorker, err := oidcmaintenance.New(oidcmaintenance.Options{
			Repository:       postgres.NewOIDCMaintenanceRepository(pool),
			Keyring:          cfg.IdentityKeyring,
			Upstream:         oidcUpstream,
			BatchSize:        cfg.OIDCMaintenanceBatchSize,
			DatabaseTimeout:  cfg.DatabaseTimeout,
			OperationTimeout: cfg.FederatedOperationTimeout,
			LeaseSafety:      cfg.OIDCMaintenanceLeaseSafety,
			PollInterval:     cfg.OIDCMaintenancePollInterval,
			Clock:            time.Now,
			Logger:           logger,
			Observer:         metrics,
			Tracer:           telemetryRuntime,
		})
		if err != nil {
			return errors.New("configure OIDC maintenance worker")
		}
		directory, err := ldapclient.New(ldapclient.Options{
			Resolver:             net.DefaultResolver,
			Dialer:               &net.Dialer{},
			PrivateEgressCIDRs:   cfg.LDAPPrivateEgressCIDRs,
			AllowedStartTLSPorts: cfg.LDAPAllowedStartTLSPorts,
			AllowedLDAPSPorts:    cfg.LDAPAllowedLDAPSPorts,
			MaxConcurrent:        cfg.LDAPMaxConcurrent,
		})
		if err != nil {
			return errors.New("configure LDAP sync client")
		}
		syncWorker, err := identitysync.New(identitysync.Options{
			Repository:       postgres.NewLDAPSyncRepository(pool),
			Directory:        directory,
			Keyring:          cfg.IdentityKeyring,
			Lease:            cfg.LDAPSyncLease,
			OperationTimeout: cfg.LDAPSyncOperationTimeout,
			TerminalTimeout:  cfg.DatabaseTimeout,
			AbsenceBatch:     cfg.LDAPSyncAbsenceBatch,
			Parallelism:      cfg.LDAPSyncParallelism,
			MinBackoff:       cfg.LDAPSyncMinBackoff,
			MaxBackoff:       cfg.LDAPSyncMaxBackoff,
			Logger:           logger,
			Observer:         metrics,
			Tracer:           telemetryRuntime,
		})
		if err != nil {
			return err
		}
		slaWorkerID, err := uuid.NewV7()
		if err != nil {
			return errors.New("create SLA worker identity")
		}
		slaRepository := postgres.NewSLARepository(pool)
		slaWorker, err := slaengine.New(
			slaRepository,
			slaengine.Identity{WorkerID: slaWorkerID, Purpose: "sla-engine"},
			slaengine.Config{
				BatchSize:         cfg.SLABatchSize,
				LeaseDuration:     cfg.SLALeaseDuration,
				OperationTimeout:  cfg.SLAOperationTimeout,
				RunTimeout:        cfg.SLARunTimeout,
				MaximumAttempts:   slaMaximumAttempts,
				RetryBaseDelay:    cfg.SLARetryBaseDelay,
				RetryMaximumDelay: cfg.SLARetryMaximumDelay,
			},
			time.Now,
		)
		if err != nil {
			return errors.New("configure SLA worker")
		}
		slaEventWorkerID, err := uuid.NewV7()
		if err != nil {
			return errors.New("create SLA event ingress worker identity")
		}
		slaEventRepository := postgres.NewSLAEventRepository(pool)
		slaEventWorker, err := slaevent.New(
			slaEventRepository,
			slaevent.Identity{WorkerID: slaEventWorkerID, Purpose: slaevent.WorkerPurpose},
			slaevent.Config{
				BatchSize:         cfg.SLAEventBatchSize,
				LeaseDuration:     cfg.SLAEventLeaseDuration,
				OperationTimeout:  cfg.SLAEventOperationTimeout,
				RunTimeout:        cfg.SLAEventRunTimeout,
				MaximumAttempts:   slaEventMaximumAttempts,
				RetryBaseDelay:    cfg.SLAEventRetryBaseDelay,
				RetryMaximumDelay: cfg.SLAEventRetryMaximumDelay,
			},
			time.Now,
		)
		if err != nil {
			return errors.New("configure SLA event ingress worker")
		}
		slaActionWorkerID, err := uuid.NewV7()
		if err != nil {
			return errors.New("create SLA action worker identity")
		}
		slaActionRepository := postgres.NewSLAActionRepository(pool)
		slaActionWorker, err := slaaction.New(slaaction.Options{
			Repository: slaActionRepository,
			Identity: slaaction.Identity{
				WorkerID: slaActionWorkerID,
				Purpose:  slaaction.WorkerPurpose,
			},
			BatchSize:        cfg.SLAActionBatchSize,
			LeaseDuration:    cfg.SLAActionLeaseDuration,
			OperationTimeout: cfg.SLAActionOperationTimeout,
			LeaseSafety:      cfg.SLAActionLeaseSafety,
			Clock:            time.Now,
		})
		if err != nil {
			return errors.New("configure SLA action worker")
		}
		dfirStorageConfig, err := dfircleanup.LoadS3Config(cfg.Environment)
		if err != nil {
			return errors.New("configure DFIR worker object storage")
		}
		dfirStorageClient, err := dfircleanup.NewS3Client(dfirStorageConfig)
		dfirStorageConfig.ClearSecrets()
		if err != nil {
			return errors.New("configure DFIR worker object storage")
		}
		defer dfircleanup.CloseS3Client(dfirStorageClient)
		dfirStore, err := dfirscan.NewS3Store(
			dfirStorageClient, dfirStorageConfig.Bucket(), cfg.DFIRMaximumObjectBytes,
			cfg.TicketExportExpectedOwner,
		)
		if err != nil {
			return errors.New("configure DFIR scan object reader")
		}
		dfirDeleter, err := dfircleanup.NewS3DeleterFromClient(
			dfirStorageClient, dfirStorageConfig.Bucket(), cfg.TicketExportExpectedOwner,
		)
		if err != nil {
			return errors.New("configure DFIR orphan object deleter")
		}
		scannerConfig, err := dfirscan.LoadClamAVConfig(cfg.Environment)
		if err != nil {
			return errors.New("configure DFIR malware scanner")
		}
		scanner, err := dfirscan.NewClamAV(scannerConfig)
		if err != nil {
			return errors.New("configure DFIR malware scanner")
		}
		dfirWorkerID, err := uuid.NewV7()
		if err != nil {
			return errors.New("create DFIR scan worker identity")
		}
		dfirScanWorker, err := dfirscan.New(dfirscan.Options{
			Repository: postgres.NewDFIRScanRepository(pool), Store: dfirStore, Scanner: scanner,
			WorkerID: dfirWorkerID, BatchSize: cfg.DFIRScanBatchSize,
			LeaseDuration: cfg.DFIRScanLeaseDuration, OperationTimeout: cfg.DFIRScanOperationTimeout,
			UploadPollDelay: cfg.DFIRScanUploadPollDelay, RetryBaseDelay: cfg.DFIRScanRetryBaseDelay,
			RetryMaximumDelay: cfg.DFIRScanRetryMaximumDelay, MaximumObjectSize: cfg.DFIRMaximumObjectBytes,
			Clock: time.Now, NewID: uuid.NewV7,
		})
		if err != nil {
			return errors.New("configure DFIR scan worker")
		}
		dfirCleanupWorker, err := dfircleanup.New(dfircleanup.Options{
			Repository: postgres.NewDFIRCleanupRepository(pool), Deleter: dfirDeleter,
			BatchSize: cfg.DFIRCleanupBatchSize, LeaseDuration: cfg.DFIRCleanupLeaseDuration,
			DeleteTimeout: cfg.DFIRCleanupDeleteTimeout, RetryBase: cfg.DFIRCleanupRetryBaseDelay,
			Clock: time.Now, NewID: uuid.NewV7,
		})
		if err != nil {
			return errors.New("configure DFIR orphan cleanup worker")
		}
		if cfg.AuditOperationsEnabled {
			auditSigner, err := auditoperations.LoadEd25519Signer(
				cfg.AuditRetentionSigningKeyFile,
				cfg.AuditRetentionSigningKeyID,
			)
			if err != nil {
				return errors.New("configure audit retention signer")
			}
			auditWorkerID, err := uuid.NewV7()
			if err != nil {
				return errors.New("create audit operations worker identity")
			}
			auditStorageConfig, err := dfircleanup.LoadS3Config(cfg.Environment)
			if err != nil {
				return errors.New("configure audit operations object storage")
			}
			auditStorageClient, err := dfircleanup.NewS3Client(auditStorageConfig)
			auditStorageConfig.ClearSecrets()
			if err != nil {
				return errors.New("configure audit operations object storage")
			}
			defer dfircleanup.CloseS3Client(auditStorageClient)
			auditStore, err := auditoperations.NewS3Store(auditStorageClient, auditoperations.S3Options{
				Bucket: auditStorageConfig.Bucket(), ExpectedBucketOwner: cfg.TicketExportExpectedOwner,
			})
			if err != nil {
				return errors.New("configure audit operations artifact store")
			}
			auditWorker, err := auditoperations.New(auditoperations.Options{
				Repository: postgres.NewAuditOperationsRepository(pool), Artifacts: auditStore,
				Signer: auditSigner, WorkerID: auditWorkerID, PageSize: auditoperations.MaximumPageSize,
				TenantBatch: 100, RetentionRows: 10_000, ReceiptBatch: 1_000,
				LeaseDuration: 10 * time.Minute, OperationTimeout: 30 * time.Second,
				SpoolDirectory: cfg.AuditOperationsSpoolDirectory, NewID: uuid.NewV7,
			})
			if err != nil {
				return errors.New("configure audit operations worker")
			}
			background.Add(1)
			go func() {
				defer background.Done()
				runAuditOperations(ctx, auditWorker, cfg.PollInterval, &ready, logger)
			}()
		} else {
			ready.audit.Store(true)
			logger.Warn("audit operations worker is not configured", "failure", "retention_signing_key_missing")
		}
		if cfg.TicketRuntimeServiceAccountID != uuid.Nil {
			serviceAccountID, err := workerEntityID(cfg.TicketRuntimeServiceAccountID)
			if err != nil {
				return errors.New("configure ticket runtime service identity")
			}
			workerUUID, err := uuid.NewV7()
			if err != nil {
				return errors.New("create ticket runtime worker identity")
			}
			workerID, err := workerEntityID(workerUUID)
			if err != nil {
				return errors.New("configure ticket runtime worker identity")
			}
			customFieldImportWorker, err := customfieldimport.New(customfieldimport.Options{
				Repository: postgres.NewCustomFieldImportWorkerRepository(pool),
				Identity: customfieldimport.Identity{
					ServiceAccountID: cfg.TicketRuntimeServiceAccountID,
					WorkerID:         workerUUID,
				},
				BatchSize: 100, LeaseDuration: 2 * time.Minute,
				LeaseSafety: 30 * time.Second, Clock: time.Now,
			})
			if err != nil {
				return errors.New("configure custom-field import worker")
			}
			storageConfig, err := dfircleanup.LoadS3Config(cfg.Environment)
			if err != nil {
				return errors.New("configure ticket export object storage")
			}
			storageClient, err := dfircleanup.NewS3Client(storageConfig)
			storageConfig.ClearSecrets()
			if err != nil {
				return errors.New("configure ticket export object storage")
			}
			defer dfircleanup.CloseS3Client(storageClient)
			artifactStore, err := ticketexport.NewS3ArtifactStore(storageClient, ticketexport.S3ArtifactOptions{
				Bucket: storageConfig.Bucket(), ExpectedBucketOwner: cfg.TicketExportExpectedOwner,
				TemporaryDirectory: cfg.TicketExportSpoolDirectory,
			})
			if err != nil {
				return errors.New("configure ticket export artifact store")
			}
			ticketRepository := postgres.NewTicketRuntimeRepository(pool)
			bulkWorker, err := ticketbulk.New(ticketbulk.Options{
				Repository: ticketRepository,
				Identity: ticketbulk.Identity{
					ServiceAccountID: serviceAccountID, WorkerID: workerID, Purpose: ticketbulk.WorkerPurpose,
				},
				BatchSize: 50, LeaseDuration: 5 * time.Minute, AttemptTimeout: 4 * time.Minute,
				OperationTimeout: 5 * time.Second, LeaseSafety: 30 * time.Second,
				RetryBase: 5 * time.Second, RetryMaximum: 5 * time.Minute, Clock: time.Now,
			})
			if err != nil {
				return errors.New("configure ticket bulk worker")
			}
			exportWorker, err := ticketexport.New(ticketexport.Options{
				Repository: ticketRepository, Artifacts: artifactStore,
				Identity: ticketexport.Identity{
					ServiceAccountID: serviceAccountID, WorkerID: workerID, Purpose: ticketexport.WorkerPurpose,
				},
				PageSize: ticketexport.MaximumPageSize, LeaseDuration: 10 * time.Minute,
				AttemptTimeout: 8 * time.Minute, OperationTimeout: 30 * time.Second,
				LeaseSafety: time.Minute, CleanupTimeout: 10 * time.Second, CleanupAttempts: 3,
				RetryBase: 5 * time.Second, RetryMaximum: 5 * time.Minute, Clock: time.Now,
				NewArtifactID: newWorkerEntityID,
			})
			if err != nil {
				return errors.New("configure ticket export worker")
			}
			reconcileWorker, err := ticketexport.NewReconciler(ticketexport.ReconcileOptions{
				Repository: ticketRepository, Artifacts: artifactStore,
				Identity: ticketexport.ReconcileIdentity{
					ServiceAccountID: serviceAccountID, WorkerID: workerID,
					Purpose: ticketexport.ReconcileWorkerPurpose,
				},
				BatchSize:        cfg.TicketExportReconcileBatch,
				MaximumAttempts:  cfg.TicketExportReconcileAttempts,
				LeaseDuration:    cfg.TicketExportReconcileLease,
				OperationTimeout: cfg.TicketExportReconcileTimeout,
				LeaseSafety:      cfg.TicketExportReconcileSafety,
				RetryBase:        cfg.TicketExportReconcileRetry,
				RetryMaximum:     cfg.TicketExportReconcileRetryMax,
				Clock:            time.Now,
			})
			if err != nil {
				return errors.New("configure ticket export reconciliation worker")
			}
			background.Add(2)
			go func() {
				defer background.Done()
				runTicketRuntime(
					ctx, ticketRepository, bulkWorker, exportWorker, reconcileWorker, artifactStore,
					serviceAccountID, workerID, cfg.PollInterval, cfg.DatabaseTimeout,
					&ready, logger, metrics, telemetryRuntime,
				)
			}()
			go func() {
				defer background.Done()
				runCustomFieldImportRuntime(
					ctx, customFieldImportWorker, cfg.PollInterval, cfg.DatabaseTimeout,
					&ready, logger,
				)
			}()
		} else {
			logger.Warn("ticket runtime is not configured", "failure", "service_identity_missing")
		}
		background.Add(9)
		go func() {
			defer background.Done()
			runDFIRScanRuntime(
				ctx, dfirScanWorker, cfg.DFIRScanPollInterval, cfg.DFIRScanOperationTimeout,
				&ready, logger, metrics,
			)
		}()
		go func() {
			defer background.Done()
			runDFIRCleanupRuntime(
				ctx, dfirCleanupWorker, cfg.DFIRCleanupPollInterval,
				cfg.DFIRCleanupLeaseDuration, &ready, logger, metrics,
			)
		}()
		go func() {
			defer background.Done()
			monitorDatabase(
				ctx,
				postgres.NewHealthChecker(pool, identityReadiness),
				cfg.PollInterval,
				cfg.DatabaseTimeout,
				&ready,
				metrics,
				telemetryRuntime,
			)
		}()
		go func() {
			defer background.Done()
			maintainAuthenticationState(
				ctx,
				postgres.NewAuthStateCleaner(pool),
				cfg.AuthCleanupInterval,
				cfg.DatabaseTimeout,
				cfg.AuthCleanupBatch,
				&ready,
				logger,
				metrics,
				telemetryRuntime,
			)
		}()
		go func() {
			defer background.Done()
			syncWorker.Run(ctx, func(value bool) {
				ready.sync.Store(value)
				metrics.SetLDAPSyncReady(value)
			})
			ready.sync.Store(false)
			metrics.SetLDAPSyncReady(false)
		}()
		go func() {
			defer background.Done()
			oidcMaintenanceWorker.Run(ctx, func(value bool) {
				ready.oidcMaintenance.Store(value)
			})
			ready.oidcMaintenance.Store(false)
		}()
		go func() {
			defer background.Done()
			runSLAEventIngress(
				ctx,
				slaEventWorker,
				slaEventRepository,
				cfg.SLAEventPollInterval,
				cfg.SLAEventRunTimeout,
				cfg.SLAEventOperationTimeout,
				&ready,
				logger,
				metrics,
				telemetryRuntime,
			)
		}()
		go func() {
			defer background.Done()
			runSLAEngine(
				ctx,
				slaWorker,
				slaRepository,
				cfg.SLAPollInterval,
				cfg.SLARunTimeout,
				cfg.SLAOperationTimeout,
				&ready,
				logger,
				metrics,
				telemetryRuntime,
			)
		}()
		go func() {
			defer background.Done()
			runSLAActionWorker(
				ctx,
				slaActionWorker,
				slaActionRepository,
				cfg.SLAActionPollInterval,
				cfg.SLAActionRunTimeout,
				cfg.SLAActionOperationTimeout,
				cfg.SLAActionQueueLimit,
				&ready,
				logger,
				metrics,
				telemetryRuntime,
				time.Now,
			)
		}()
	}

	mux := newWorkerHandler(cfg.Release, &ready, metrics)

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           telemetryRuntime.WrapHTTP(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("worker started", "address", cfg.Address, "release", cfg.Release)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownContext)
		if shutdownErr != nil {
			_ = server.Close()
		}
		listenErr := <-serverErrors
		if !waitForBackground(shutdownContext, &background) {
			return errors.New("worker background shutdown timed out")
		}
		if shutdownErr != nil {
			return shutdownErr
		}
		if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			return listenErr
		}
		return nil
	case err := <-serverErrors:
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if !waitForBackground(shutdownContext, &background) {
			return errors.New("worker background shutdown timed out")
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func newWorkerHandler(release string, ready *workerReadiness, metrics *telemetry.Metrics) http.Handler {
	if ready == nil || metrics == nil {
		panic("worker HTTP dependencies are required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "alive", "service": "worker", "version": release})
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Ready() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"type": "about:blank", "title": "Service unavailable", "status": http.StatusServiceUnavailable,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(metrics.RenderPrometheus()))
	})
	return mux
}

func waitForBackground(ctx context.Context, background *sync.WaitGroup) bool {
	done := make(chan struct{})
	go func() {
		background.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

func databasePoolConfig(
	databaseURL string,
	databaseTimeout time.Duration,
	telemetryRuntime *telemetry.Runtime,
) (*pgxpool.Config, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("parse database configuration")
	}
	pinDatabaseRuntimeParam(poolConfig.ConnConfig.RuntimeParams, "application_name", "periapsis-worker")
	pinDatabaseRuntimeParam(poolConfig.ConnConfig.RuntimeParams, "timezone", "UTC")
	pinDatabaseRuntimeParam(
		poolConfig.ConnConfig.RuntimeParams,
		"statement_timeout",
		strconv.FormatInt(databaseTimeout.Milliseconds(), 10),
	)
	pinDatabaseRuntimeParam(
		poolConfig.ConnConfig.RuntimeParams,
		"lock_timeout",
		strconv.FormatInt(databaseTimeout.Milliseconds(), 10),
	)
	pinDatabaseRuntimeParam(
		poolConfig.ConnConfig.RuntimeParams,
		"idle_in_transaction_session_timeout",
		strconv.FormatInt((2*databaseTimeout).Milliseconds(), 10),
	)
	if err := telemetryRuntime.InstrumentPGX(poolConfig); err != nil {
		return nil, err
	}
	return poolConfig, nil
}

func pinDatabaseRuntimeParam(runtimeParams map[string]string, name, value string) {
	for existingName := range runtimeParams {
		if strings.EqualFold(existingName, name) {
			delete(runtimeParams, existingName)
		}
	}
	runtimeParams[name] = value
}

type readinessChecker interface {
	Check(context.Context) bool
}

type authStatePruner interface {
	Prune(context.Context, int) (postgres.AuthStateCleanupCounts, error)
}

type auditOperationsRunner interface {
	Check(context.Context) error
	RunOnce(context.Context) (auditoperations.Summary, error)
}

type dfirScanRunner interface {
	Check(context.Context) error
	RunOnce(context.Context) (dfirscan.Result, error)
}

type dfirCleanupRunner interface {
	Check(context.Context) error
	RunOnce(context.Context) (dfircleanup.Result, error)
}

type workerReadiness struct {
	audit             atomic.Bool
	database          atomic.Bool
	cleanup           atomic.Bool
	dfirCleanup       atomic.Bool
	dfirScan          atomic.Bool
	sync              atomic.Bool
	sla               atomic.Bool
	slaAction         atomic.Bool
	slaEvent          atomic.Bool
	ticket            atomic.Bool
	customFieldImport atomic.Bool
	oidcMaintenance   atomic.Bool
}

func (r *workerReadiness) Ready() bool {
	return r.audit.Load() && r.database.Load() && r.cleanup.Load() && r.sync.Load() && r.sla.Load() &&
		r.slaAction.Load() && r.slaEvent.Load() && r.ticket.Load() && r.customFieldImport.Load() &&
		r.oidcMaintenance.Load() && r.dfirScan.Load() && r.dfirCleanup.Load()
}

func runDFIRScanRuntime(
	ctx context.Context,
	worker dfirScanRunner,
	interval time.Duration,
	operationTimeout time.Duration,
	ready *workerReadiness,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
) {
	if ctx == nil || workerDependencyIsNil(worker) || interval <= 0 || operationTimeout <= 0 ||
		ready == nil || logger == nil || metrics == nil {
		return
	}
	defer func() {
		ready.dfirScan.Store(false)
		metrics.SetDFIRScanReady(false)
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		checkContext, cancelCheck := context.WithTimeout(ctx, min(operationTimeout, 10*time.Second))
		checkErr := worker.Check(checkContext)
		cancelCheck()
		iterationHealthy := checkErr == nil && ctx.Err() == nil
		var result dfirscan.Result
		var runErr error
		if iterationHealthy {
			runContext, cancelRun := context.WithTimeout(ctx, operationTimeout)
			result, runErr = worker.RunOnce(runContext)
			cancelRun()
			iterationHealthy = runErr == nil && ctx.Err() == nil
			metrics.ObserveDFIRScanRun(
				result.Claimed, result.Available, result.Rejected, result.ScanFailed,
				result.WaitingUpload, result.UploadExpired, result.RetryScheduled, result.FenceLost, runErr,
			)
		}
		ready.dfirScan.Store(iterationHealthy)
		metrics.SetDFIRScanReady(iterationHealthy)
		if !iterationHealthy && ctx.Err() == nil {
			logger.Warn("DFIR scan cycle failed", "failure", "dependency_unavailable")
		} else if result.Claimed > 0 {
			logger.Info(
				"DFIR scan cycle completed", "claimed", result.Claimed,
				"available", result.Available, "rejected", result.Rejected,
				"scan_failed", result.ScanFailed, "waiting_upload", result.WaitingUpload,
				"upload_expired", result.UploadExpired, "retry_scheduled", result.RetryScheduled,
				"fence_lost", result.FenceLost,
			)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runDFIRCleanupRuntime(
	ctx context.Context,
	worker dfirCleanupRunner,
	interval time.Duration,
	runTimeout time.Duration,
	ready *workerReadiness,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
) {
	if ctx == nil || workerDependencyIsNil(worker) || interval <= 0 || runTimeout <= 0 ||
		ready == nil || logger == nil || metrics == nil {
		return
	}
	defer func() {
		ready.dfirCleanup.Store(false)
		metrics.SetDFIRCleanupReady(false)
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		checkContext, cancelCheck := context.WithTimeout(ctx, min(runTimeout, 10*time.Second))
		checkErr := worker.Check(checkContext)
		cancelCheck()
		healthy := checkErr == nil && ctx.Err() == nil
		var result dfircleanup.Result
		var runErr error
		if healthy {
			runContext, cancelRun := context.WithTimeout(ctx, runTimeout)
			result, runErr = worker.RunOnce(runContext)
			cancelRun()
			healthy = runErr == nil && ctx.Err() == nil
			metrics.ObserveDFIRCleanupRun(result.Claimed, result.Deleted, result.Retryable, runErr)
		}
		ready.dfirCleanup.Store(healthy)
		metrics.SetDFIRCleanupReady(healthy)
		if !healthy && ctx.Err() == nil {
			logger.Warn("DFIR orphan cleanup cycle failed", "failure", "dependency_unavailable")
		} else if result.Claimed > 0 {
			logger.Info(
				"DFIR orphan cleanup cycle completed", "claimed", result.Claimed,
				"deleted", result.Deleted, "retry_scheduled", result.Retryable,
			)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type customFieldImportRunner interface {
	Ready(context.Context) error
	ListQueues(context.Context, int) ([]customfieldimport.Queue, error)
	RunOnce(context.Context, customfieldimport.Queue) (customfieldimport.Result, error)
}

func runCustomFieldImportRuntime(
	ctx context.Context,
	worker customFieldImportRunner,
	interval time.Duration,
	operationTimeout time.Duration,
	ready *workerReadiness,
	logger *slog.Logger,
) {
	if ready == nil {
		return
	}
	defer ready.customFieldImport.Store(false)
	if ctx == nil || ctx.Err() != nil || workerDependencyIsNil(worker) || interval <= 0 ||
		operationTimeout <= 0 || logger == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		checkContext, cancelCheck := context.WithTimeout(ctx, operationTimeout)
		checkErr := worker.Ready(checkContext)
		cancelCheck()
		iterationHealthy := checkErr == nil && ctx.Err() == nil
		if iterationHealthy {
			queueContext, cancelQueues := context.WithTimeout(ctx, operationTimeout)
			queues, queueErr := worker.ListQueues(queueContext, 100)
			cancelQueues()
			iterationHealthy = queueErr == nil && ctx.Err() == nil
			if iterationHealthy {
				for _, queue := range queues {
					runContext, cancelRun := context.WithTimeout(ctx, 4*time.Minute)
					result, runErr := worker.RunOnce(runContext, queue)
					cancelRun()
					if runErr != nil {
						iterationHealthy = false
						if ctx.Err() == nil {
							logger.Warn("custom-field import cycle failed", "failure", "dependency_unavailable")
						}
						break
					}
					if result.DidWork {
						logger.Info(
							"custom-field import cycle completed",
							"state", result.State.String(), "rows", result.Rows,
						)
					}
				}
			}
		} else if ctx.Err() == nil {
			logger.Warn("custom-field import readiness failed", "failure", "database_abi_unavailable")
		}
		ready.customFieldImport.Store(iterationHealthy)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runAuditOperations(
	ctx context.Context,
	worker auditOperationsRunner,
	interval time.Duration,
	ready *workerReadiness,
	logger *slog.Logger,
) {
	if ctx == nil || workerDependencyIsNil(worker) || interval <= 0 || ready == nil || logger == nil {
		return
	}
	defer ready.audit.Store(false)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		checkContext, cancelCheck := context.WithTimeout(ctx, 30*time.Second)
		checkErr := worker.Check(checkContext)
		cancelCheck()
		if checkErr == nil {
			runContext, cancelRun := context.WithTimeout(ctx, 9*time.Minute)
			summary, runErr := worker.RunOnce(runContext)
			cancelRun()
			ready.audit.Store(runErr == nil)
			if runErr != nil && ctx.Err() == nil {
				logger.Warn("audit operations cycle failed", "failure", "dependency_unavailable")
			} else if summary.DidWork() {
				logger.Info(
					"audit operations cycle completed",
					"exports_claimed", summary.ExportsClaimed,
					"exports_succeeded", summary.ExportsSucceeded,
					"exports_discarded", summary.ExportsDiscarded,
					"segments_preserved", summary.SegmentsPreserved,
					"segments_pruned", summary.SegmentsPruned,
					"receipts_pruned", summary.ReceiptsPruned,
				)
			}
		} else {
			ready.audit.Store(false)
			if ctx.Err() == nil {
				logger.Warn("audit operations readiness failed", "failure", "storage_unavailable")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type slaRunner interface {
	RunOnce(context.Context) (slaengine.RunSummary, error)
}

type slaQueueReader interface {
	ReadQueueMetrics(context.Context) (postgres.SLAQueueMetrics, error)
}

type slaActionRunner interface {
	RunOnce(context.Context, slaaction.Queue) (slaaction.Summary, error)
}

type slaActionRuntime interface {
	Ready(context.Context) error
	ListQueues(context.Context, time.Time, int) ([]slaaction.Queue, error)
	ReadQueueMetrics(context.Context) (postgres.SLAActionQueueMetrics, error)
}

type slaEventRunner interface {
	RunOnce(context.Context) (slaevent.RunSummary, error)
}

type slaEventRuntime interface {
	Ready(context.Context) error
	ReadQueueMetrics(context.Context) (slaevent.QueueMetrics, error)
}

type ticketRuntimeRepository interface {
	Ready(context.Context) error
	ListQueues(context.Context, kernel.EntityID, kernel.EntityID, int) ([]postgres.TicketWorkQueue, error)
	ReadReconciliationMetrics(
		context.Context,
		ticketexport.ReconcileIdentity,
	) (postgres.TicketExportReconciliationMetrics, error)
}

type ticketBulkRunner interface {
	RunOnce(context.Context, ticketbulk.Queue) (ticketbulk.Result, error)
}

type ticketExportRunner interface {
	RunOnce(context.Context, ticketexport.Queue) (ticketexport.Result, error)
}

type ticketReconcileRunner interface {
	RunOnce(context.Context, ticketexport.Queue) (ticketexport.ReconcileSummary, error)
}

type ticketArtifactRuntime interface {
	Check(context.Context) error
	SweepSpoolsBefore(context.Context, time.Time, int) (ticketexport.SpoolSweepResult, error)
}

func runTicketRuntime(
	ctx context.Context,
	repository ticketRuntimeRepository,
	bulk ticketBulkRunner,
	export ticketExportRunner,
	reconcile ticketReconcileRunner,
	artifacts ticketArtifactRuntime,
	serviceAccountID kernel.EntityID,
	workerID kernel.EntityID,
	interval time.Duration,
	operationTimeout time.Duration,
	ready *workerReadiness,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
	tracer identitysync.OperationTracer,
) {
	if ready == nil || metrics == nil {
		return
	}
	defer func() {
		ready.ticket.Store(false)
		metrics.SetTicketRuntimeReady(false)
		metrics.ClearTicketExportReconciliationQueueObservation()
	}()
	if ctx == nil || ctx.Err() != nil || workerDependencyIsNil(repository) ||
		workerDependencyIsNil(bulk) || workerDependencyIsNil(export) ||
		workerDependencyIsNil(reconcile) || workerDependencyIsNil(artifacts) ||
		logger == nil || interval <= 0 || operationTimeout <= 0 ||
		!validWorkerEntityID(serviceAccountID) || !validWorkerEntityID(workerID) {
		return
	}
	reconciliationIdentity := ticketexport.ReconcileIdentity{
		ServiceAccountID: serviceAccountID,
		WorkerID:         workerID,
		Purpose:          ticketexport.ReconcileWorkerPurpose,
	}
	lastSweep := time.Time{}
	run := func() bool {
		if ctx.Err() != nil {
			return false
		}
		iterationHealthy := true
		checkContext, cancelCheck := context.WithTimeout(ctx, operationTimeout)
		finishTrace := func(error) {}
		if tracer != nil {
			checkContext, finishTrace = tracer.StartOperation(checkContext, "ticket.runtime.readiness")
		}
		err := repository.Ready(checkContext)
		finishTrace(err)
		cancelCheck()
		if err != nil || ctx.Err() != nil {
			ready.ticket.Store(false)
			metrics.SetTicketRuntimeReady(false)
			metrics.ClearTicketExportReconciliationQueueObservation()
			if ctx.Err() == nil {
				logger.Warn("ticket runtime readiness failed", "failure", classifyTicketRuntimeFailure(err))
			}
			return ctx.Err() == nil
		}
		storageContext, cancelStorage := context.WithTimeout(ctx, operationTimeout)
		storageErr := artifacts.Check(storageContext)
		cancelStorage()
		if storageErr != nil || ctx.Err() != nil {
			ready.ticket.Store(false)
			metrics.SetTicketRuntimeReady(false)
			metrics.ClearTicketExportReconciliationQueueObservation()
			if ctx.Err() == nil {
				logger.Warn("ticket export storage readiness failed", "failure", classifyTicketRuntimeFailure(storageErr))
			}
			return ctx.Err() == nil
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		if lastSweep.IsZero() || now.Sub(lastSweep) >= time.Hour {
			sweepContext, cancelSweep := context.WithTimeout(ctx, operationTimeout)
			_, sweepErr := artifacts.SweepSpoolsBefore(
				sweepContext, now.Add(-ticketexport.MinimumSpoolSweepAge),
				ticketexport.MaximumSpoolSweepEntries,
			)
			cancelSweep()
			if sweepErr != nil {
				iterationHealthy = false
				logger.Warn("ticket export spool reconciliation failed", "failure", classifyTicketRuntimeFailure(sweepErr))
			} else {
				lastSweep = now
			}
		}

		queueContext, cancelQueues := context.WithTimeout(ctx, operationTimeout)
		queues, queueErr := repository.ListQueues(queueContext, serviceAccountID, workerID, 256)
		cancelQueues()
		if queueErr != nil || ctx.Err() != nil {
			ready.ticket.Store(false)
			metrics.SetTicketRuntimeReady(false)
			metrics.ClearTicketExportReconciliationQueueObservation()
			if ctx.Err() == nil {
				logger.Warn("ticket work queue discovery failed", "failure", classifyTicketRuntimeFailure(queueErr))
			}
			return ctx.Err() == nil
		}
		if !runTicketQueueFamilies(ctx, queues, bulk, export, reconcile, logger, metrics, tracer) {
			iterationHealthy = false
		}
		observationContext, cancelObservation := context.WithTimeout(ctx, operationTimeout)
		finishObservationTrace := func(error) {}
		if tracer != nil {
			observationContext, finishObservationTrace = tracer.StartOperation(
				observationContext,
				"ticket.export.reconcile.metrics",
			)
		}
		observation, observationErr := repository.ReadReconciliationMetrics(
			observationContext,
			reconciliationIdentity,
		)
		if observationErr == nil && !metrics.SetTicketExportReconciliationQueueObservation(
			observation.PendingEligible,
			observation.Reclaimable,
			observation.DeadLettered,
			observation.OldestPendingMicros,
		) {
			observationErr = errors.New("ticket export reconciliation queue observation is invalid")
		}
		finishObservationTrace(observationErr)
		cancelObservation()
		if observationErr != nil {
			iterationHealthy = false
			metrics.ClearTicketExportReconciliationQueueObservation()
			if ctx.Err() == nil {
				logger.Warn(
					"ticket export reconciliation queue observation failed",
					"failure", classifyTicketRuntimeFailure(observationErr),
				)
			}
		}
		if ctx.Err() != nil {
			return false
		}
		ready.ticket.Store(iterationHealthy)
		metrics.SetTicketRuntimeReady(iterationHealthy)
		return true
	}
	if !run() {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !run() {
				return
			}
		}
	}
}

func runTicketQueueFamilies(
	ctx context.Context,
	queues []postgres.TicketWorkQueue,
	bulk ticketBulkRunner,
	export ticketExportRunner,
	reconcile ticketReconcileRunner,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
	tracer identitysync.OperationTracer,
) bool {
	bulkQueues := make([]postgres.TicketWorkQueue, 0, len(queues))
	exportQueues := make([]postgres.TicketWorkQueue, 0, len(queues))
	for _, queue := range queues {
		if queue.Export {
			exportQueues = append(exportQueues, queue)
		} else {
			bulkQueues = append(bulkQueues, queue)
		}
	}
	results := make(chan bool, 3)
	go func() {
		healthy := true
		for _, queue := range bulkQueues {
			if ctx.Err() != nil {
				healthy = false
				break
			}
			runContext := ctx
			finishTrace := func(error) {}
			if tracer != nil {
				runContext, finishTrace = tracer.StartOperation(ctx, "ticket.bulk")
			}
			result, runErr := bulk.RunOnce(runContext, ticketbulk.Queue{TenantID: queue.TenantID, Kind: queue.Kind})
			if runErr == nil && result.Outcome == ticketbulk.OutcomeUnknown {
				runErr = errors.New("ticket bulk worker returned an invalid outcome")
			}
			if !metrics.ObserveTicketRuntimeRun("bulk", result.Claimed, runErr) {
				runErr = errors.Join(runErr, errors.New("ticket bulk metric invariant failed"))
			}
			finishTrace(runErr)
			if runErr != nil {
				healthy = false
				logger.WarnContext(runContext, "ticket bulk run failed", "failure", classifyTicketRuntimeFailure(runErr))
			}
		}
		results <- healthy
	}()
	go func() {
		healthy := true
		for _, queue := range exportQueues {
			if ctx.Err() != nil {
				healthy = false
				break
			}
			runContext := ctx
			finishTrace := func(error) {}
			if tracer != nil {
				runContext, finishTrace = tracer.StartOperation(ctx, "ticket.export")
			}
			result, runErr := export.RunOnce(runContext, ticketexport.Queue{
				TenantID: queue.TenantID, Kind: queue.Kind, Audience: queue.Audience,
			})
			if runErr == nil && result.Outcome == ticketexport.OutcomeUnknown {
				runErr = errors.New("ticket export worker returned an invalid outcome")
			}
			if !metrics.ObserveTicketRuntimeRun("export", result.Claimed, runErr) {
				runErr = errors.Join(runErr, errors.New("ticket export metric invariant failed"))
			}
			finishTrace(runErr)
			if runErr != nil {
				healthy = false
				logger.WarnContext(runContext, "ticket export run failed", "failure", classifyTicketRuntimeFailure(runErr))
			}
		}
		results <- healthy
	}()
	go func() {
		healthy := true
		for _, queue := range exportQueues {
			if ctx.Err() != nil {
				healthy = false
				break
			}
			runContext := ctx
			finishTrace := func(error) {}
			if tracer != nil {
				runContext, finishTrace = tracer.StartOperation(ctx, "ticket.export.reconcile")
			}
			summary, runErr := reconcile.RunOnce(runContext, ticketexport.Queue{
				TenantID: queue.TenantID, Kind: queue.Kind, Audience: queue.Audience,
			})
			if !metrics.ObserveTicketExportReconciliation(
				summary.Claimed, summary.Purged, summary.Replayed,
				summary.RetryScheduled, summary.DeadLettered, summary.FenceLost,
				runErr,
			) {
				runErr = errors.Join(runErr, errors.New("ticket export reconciliation metric invariant failed"))
			}
			finishTrace(runErr)
			if runErr != nil {
				healthy = false
				logger.WarnContext(
					runContext, "ticket export reconciliation run failed",
					"failure", classifyTicketRuntimeFailure(runErr),
				)
			}
		}
		results <- healthy
	}()
	first, second, third := <-results, <-results, <-results
	return first && second && third
}

func classifyTicketRuntimeFailure(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ticketbulk.ErrFenceLost), errors.Is(err, ticketexport.ErrFenceLost):
		return "fence_lost"
	case errors.Is(err, ticketbulk.ErrInvalidInput), errors.Is(err, ticketexport.ErrInvalidInput),
		errors.Is(err, ticketbulk.ErrInvalidProjection), errors.Is(err, ticketexport.ErrInvalidProjection),
		errors.Is(err, ticketexport.ErrInvalidConfiguration):
		return "invalid_projection"
	case errors.Is(err, ticketbulk.ErrUnavailable), errors.Is(err, ticketexport.ErrUnavailable):
		return "unavailable"
	default:
		return "internal"
	}
}

func workerEntityID(value uuid.UUID) (kernel.EntityID, error) {
	return kernel.NewEntityID(value)
}

func newWorkerEntityID() (kernel.EntityID, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return kernel.EntityID{}, err
	}
	return workerEntityID(value)
}

func validWorkerEntityID(value kernel.EntityID) bool {
	restored, err := kernel.NewEntityID(value.Bytes())
	return err == nil && restored == value
}

func runSLAActionWorker(
	ctx context.Context,
	runner slaActionRunner,
	repository slaActionRuntime,
	interval time.Duration,
	runTimeout time.Duration,
	operationTimeout time.Duration,
	queueLimit int,
	ready *workerReadiness,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
	tracer identitysync.OperationTracer,
	clock func() time.Time,
) {
	if ready == nil || metrics == nil {
		return
	}
	defer func() {
		ready.slaAction.Store(false)
		metrics.SetSLAActionReady(false)
		metrics.ClearSLAActionQueueObservation()
	}()
	if ctx == nil || ctx.Err() != nil || workerDependencyIsNil(runner) ||
		workerDependencyIsNil(repository) || interval <= 0 || runTimeout <= 0 ||
		operationTimeout <= 0 || operationTimeout > runTimeout || queueLimit < 1 ||
		queueLimit > 500 || logger == nil || clock == nil {
		return
	}
	run := func() bool {
		if ctx.Err() != nil {
			return false
		}
		runContext, cancelRun := context.WithTimeout(ctx, runTimeout)
		defer cancelRun()
		finishTrace := func(error) {}
		if tracer != nil {
			runContext, finishTrace = tracer.StartOperation(runContext, "sla.action")
		}
		summary := slaaction.Summary{}
		var runErr error

		readinessContext, cancelReadiness := context.WithTimeout(runContext, operationTimeout)
		runErr = repository.Ready(readinessContext)
		cancelReadiness()
		now := clock().UTC().Truncate(time.Microsecond)
		if runErr == nil && !validSLAActionRuntimeInstant(now) {
			runErr = slaaction.ErrInvalidConfiguration
		}
		var queues []slaaction.Queue
		if runErr == nil {
			queueContext, cancelQueues := context.WithTimeout(runContext, operationTimeout)
			queues, runErr = repository.ListQueues(queueContext, now, queueLimit)
			cancelQueues()
			if runErr == nil && !validSLAActionQueues(queues, queueLimit) {
				runErr = slaaction.ErrInvalidProjection
			}
		}
		if runErr == nil {
			for _, queue := range queues {
				partial, actionErr := runner.RunOnce(runContext, queue)
				if !accumulateSLAActionSummary(&summary, partial) {
					runErr = slaaction.ErrInvalidProjection
					break
				}
				if actionErr != nil {
					runErr = actionErr
					break
				}
				if runContext.Err() != nil {
					runErr = runContext.Err()
					break
				}
			}
		}
		if runErr == nil {
			observationContext, cancelObservation := context.WithTimeout(runContext, operationTimeout)
			queue, observationErr := repository.ReadQueueMetrics(observationContext)
			cancelObservation()
			if observationErr != nil || !metrics.SetSLAActionQueueObservation(
				queue.PendingActions,
				queue.OldestPendingMicros,
			) {
				metrics.ClearSLAActionQueueObservation()
				runErr = errors.New("SLA action queue observation failed")
			}
		} else {
			metrics.ClearSLAActionQueueObservation()
		}
		if !metrics.ObserveSLAActionRun(
			summary.Claimed,
			summary.Applied,
			summary.Replayed,
			summary.RetryScheduled,
			summary.DeadLettered,
			summary.FenceLost,
			runErr,
		) {
			runErr = errors.New("SLA action worker returned an invalid summary")
		}
		finishTrace(runErr)
		if ctx.Err() != nil {
			return false
		}
		if runErr != nil {
			ready.slaAction.Store(false)
			metrics.SetSLAActionReady(false)
			logger.WarnContext(
				runContext,
				"SLA trigger action execution failed",
				"failure", classifySLAActionRunFailure(runErr),
			)
			return true
		}
		ready.slaAction.Store(true)
		metrics.SetSLAActionReady(true)
		if summary.Claimed > 0 {
			logger.InfoContext(
				runContext,
				"SLA trigger actions executed",
				"claimed", summary.Claimed,
				"applied", summary.Applied,
				"replayed", summary.Replayed,
				"retry_scheduled", summary.RetryScheduled,
				"dead_lettered", summary.DeadLettered,
				"fence_lost", summary.FenceLost,
			)
		}
		return true
	}
	if !run() {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !run() {
				return
			}
		}
	}
}

func validSLAActionRuntimeInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 &&
		value.Year() <= 9999 && value.Nanosecond()%1_000 == 0
}

func validSLAActionQueues(queues []slaaction.Queue, maximum int) bool {
	if len(queues) > maximum {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(queues))
	for _, queue := range queues {
		if queue.TenantID == uuid.Nil || queue.TenantID.Version() != 7 ||
			queue.TenantID.Variant() != uuid.RFC4122 {
			return false
		}
		if _, duplicate := seen[queue.TenantID]; duplicate {
			return false
		}
		seen[queue.TenantID] = struct{}{}
	}
	return true
}

func accumulateSLAActionSummary(total *slaaction.Summary, partial slaaction.Summary) bool {
	if total == nil || partial.Claimed < 0 || partial.Claimed > slaaction.MaximumBatchSize ||
		partial.Applied < 0 || partial.Replayed < 0 || partial.RetryScheduled < 0 ||
		partial.DeadLettered < 0 || partial.FenceLost < 0 ||
		partial.Applied+partial.Replayed+partial.RetryScheduled+partial.DeadLettered+
			partial.FenceLost > partial.Claimed ||
		total.Claimed > 500*slaaction.MaximumBatchSize-partial.Claimed {
		return false
	}
	total.Claimed += partial.Claimed
	total.Applied += partial.Applied
	total.Replayed += partial.Replayed
	total.RetryScheduled += partial.RetryScheduled
	total.DeadLettered += partial.DeadLettered
	total.FenceLost += partial.FenceLost
	return true
}

func classifySLAActionRunFailure(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, slaaction.ErrInterrupted):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, slaaction.ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, slaaction.ErrInvalidConfiguration):
		return "invalid_configuration"
	case errors.Is(err, slaaction.ErrInvalidProjection):
		return "invalid_projection"
	case errors.Is(err, slaaction.ErrUnavailable), errors.Is(err, slaaction.ErrTransitionOutcomeUnknown):
		return "unavailable"
	default:
		return "internal"
	}
}

func workerDependencyIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func runSLAEventIngress(
	ctx context.Context,
	runner slaEventRunner,
	repository slaEventRuntime,
	interval time.Duration,
	runTimeout time.Duration,
	operationTimeout time.Duration,
	ready *workerReadiness,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
	tracer identitysync.OperationTracer,
) {
	if ready == nil || metrics == nil {
		return
	}
	defer func() {
		ready.slaEvent.Store(false)
		metrics.SetSLAEventReady(false)
		metrics.ClearSLAEventQueueObservation()
	}()
	if ctx == nil || ctx.Err() != nil || workerDependencyIsNil(runner) ||
		workerDependencyIsNil(repository) || interval <= 0 || runTimeout <= 0 ||
		operationTimeout <= 0 || operationTimeout > runTimeout || logger == nil {
		return
	}
	run := func() bool {
		if ctx.Err() != nil {
			return false
		}
		runContext, cancelRun := context.WithTimeout(ctx, runTimeout)
		defer cancelRun()
		finishTrace := func(error) {}
		if tracer != nil {
			runContext, finishTrace = tracer.StartOperation(runContext, "sla.event_ingress")
		}
		summary := slaevent.RunSummary{}
		readinessContext, cancelReadiness := context.WithTimeout(runContext, operationTimeout)
		runErr := repository.Ready(readinessContext)
		cancelReadiness()
		if runErr == nil {
			summary, runErr = runner.RunOnce(runContext)
		}
		if runErr == nil {
			observationContext, cancelObservation := context.WithTimeout(runContext, operationTimeout)
			queue, observationErr := repository.ReadQueueMetrics(observationContext)
			cancelObservation()
			if observationErr != nil || !metrics.SetSLAEventQueueObservation(
				queue.PendingEvents,
				queue.ReclaimableEvents,
				queue.DeadLetteredEvents,
				queue.OldestPendingMicros,
			) {
				metrics.ClearSLAEventQueueObservation()
				runErr = errors.New("SLA event ingress queue observation failed")
			}
		} else {
			metrics.ClearSLAEventQueueObservation()
		}
		if !metrics.ObserveSLAEventRun(
			summary.Claimed,
			summary.Applied,
			summary.Replayed,
			summary.RetryScheduled,
			summary.DeadLettered,
			summary.FenceLost,
			runErr,
		) {
			runErr = errors.New("SLA event ingress worker returned an invalid summary")
		}
		finishTrace(runErr)
		if ctx.Err() != nil {
			return false
		}
		if runErr != nil {
			ready.slaEvent.Store(false)
			metrics.SetSLAEventReady(false)
			logger.WarnContext(
				runContext,
				"SLA event ingress failed",
				"failure", classifySLAEventRunFailure(runErr),
			)
			return true
		}
		ready.slaEvent.Store(true)
		metrics.SetSLAEventReady(true)
		if summary.Claimed > 0 {
			logger.InfoContext(
				runContext,
				"SLA events ingested",
				"claimed", summary.Claimed,
				"applied", summary.Applied,
				"replayed", summary.Replayed,
				"retry_scheduled", summary.RetryScheduled,
				"dead_lettered", summary.DeadLettered,
				"fence_lost", summary.FenceLost,
			)
		}
		return true
	}
	if !run() {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !run() {
				return
			}
		}
	}
}

func classifySLAEventRunFailure(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, slaevent.ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, slaevent.ErrInvalidConfiguration):
		return "invalid_configuration"
	case errors.Is(err, slaevent.ErrInvalidProjection):
		return "invalid_projection"
	case errors.Is(err, slaevent.ErrFenceLost):
		return "fence_lost"
	case errors.Is(err, slaevent.ErrUnavailable):
		return "unavailable"
	default:
		return "internal"
	}
}

func runSLAEngine(
	ctx context.Context,
	runner slaRunner,
	queueReader slaQueueReader,
	interval time.Duration,
	runTimeout time.Duration,
	observationTimeout time.Duration,
	ready *workerReadiness,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
	tracer identitysync.OperationTracer,
) {
	defer func() {
		ready.sla.Store(false)
		metrics.SetSLAReady(false)
	}()
	run := func() bool {
		if ctx.Err() != nil {
			return false
		}
		runContext, cancel := context.WithTimeout(ctx, runTimeout)
		defer cancel()
		finishTrace := func(error) {}
		if tracer != nil {
			runContext, finishTrace = tracer.StartOperation(runContext, "sla.evaluate")
		}
		summary, runErr := runner.RunOnce(runContext)
		if runErr == nil {
			observationContext, cancelObservation := context.WithTimeout(runContext, observationTimeout)
			queue, observationErr := queueReader.ReadQueueMetrics(observationContext)
			cancelObservation()
			if observationErr != nil || !metrics.SetSLAQueueObservation(
				queue.PendingJobs,
				queue.OldestPendingMicros,
			) {
				metrics.ClearSLAQueueObservation()
				runErr = errors.New("SLA queue observation failed")
			}
		} else {
			metrics.ClearSLAQueueObservation()
		}
		if !metrics.ObserveSLARun(
			summary.Claimed,
			summary.Completed,
			summary.Retryable,
			summary.DeadLettered,
			runErr,
		) {
			runErr = errors.New("SLA worker returned an invalid run summary")
		}
		finishTrace(runErr)
		if ctx.Err() != nil {
			return false
		}
		if runErr != nil {
			ready.sla.Store(false)
			metrics.SetSLAReady(false)
			logger.WarnContext(
				runContext,
				"SLA evaluation failed",
				"failure", classifySLARunFailure(runErr),
			)
			return true
		}
		ready.sla.Store(true)
		metrics.SetSLAReady(true)
		if summary.Claimed > 0 {
			logger.InfoContext(
				runContext,
				"SLA evaluation completed",
				"claimed", summary.Claimed,
				"completed", summary.Completed,
				"retryable", summary.Retryable,
				"dead_lettered", summary.DeadLettered,
			)
		}
		return true
	}
	if !run() {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !run() {
				return
			}
		}
	}
}

func classifySLARunFailure(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, slaengine.ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, slaengine.ErrUnavailable):
		return "unavailable"
	default:
		return "internal"
	}
}

func monitorDatabase(
	ctx context.Context,
	checker readinessChecker,
	interval time.Duration,
	timeout time.Duration,
	ready *workerReadiness,
	metrics *telemetry.Metrics,
	tracer identitysync.OperationTracer,
) {
	check := func() {
		checkContext, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		finishTrace := func(error) {}
		if tracer != nil {
			checkContext, finishTrace = tracer.StartOperation(checkContext, "database.readiness")
		}
		healthy := checker.Check(checkContext)
		if healthy {
			finishTrace(nil)
		} else {
			finishTrace(errors.New("database readiness failed"))
		}
		ready.database.Store(healthy)
		metrics.SetDatabaseReady(healthy)
	}
	check()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func maintainAuthenticationState(
	ctx context.Context,
	cleaner authStatePruner,
	interval time.Duration,
	timeout time.Duration,
	perClassBatchSize int,
	ready *workerReadiness,
	logger *slog.Logger,
	metrics *telemetry.Metrics,
	tracer identitysync.OperationTracer,
) {
	prune := func() {
		pruneContext, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		finishTrace := func(error) {}
		if tracer != nil {
			pruneContext, finishTrace = tracer.StartOperation(pruneContext, "auth.cleanup")
		}
		counts, err := cleaner.Prune(pruneContext, perClassBatchSize)
		finishTrace(err)
		metrics.RecordAuthCleanup(err)
		if err != nil {
			ready.cleanup.Store(false)
			metrics.SetCleanupReady(false)
			logger.WarnContext(pruneContext, "authorization state cleanup failed", "error", err)
			return
		}
		ready.cleanup.Store(true)
		metrics.SetCleanupReady(true)
		logger.InfoContext(
			pruneContext,
			"authorization state cleanup completed",
			"rate_limits_deleted", counts.RateLimits,
			"challenges_deleted", counts.Challenges,
			"sessions_deleted", counts.Sessions,
			"platform_commands_deleted", counts.PlatformCommands,
			"tenant_commands_deleted", counts.TenantCommands,
			"tenant_membership_lifecycle_commands_deleted", counts.TenantMembershipLifecycleCommands,
			"dfir_mutation_command_results_deleted", counts.DFIRMutationCommandResults,
			"dfir_mutation_commands_deleted", counts.DFIRMutationCommands,
		)
	}

	prune()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
