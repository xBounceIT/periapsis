package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/alert"
	"github.com/periapsis-im/periapsis/services/api/internal/apiratelimit"
	"github.com/periapsis-im/periapsis/services/api/internal/auditoperations"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/config"
	"github.com/periapsis-im/periapsis/services/api/internal/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/customfieldimport"
	"github.com/periapsis-im/periapsis/services/api/internal/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/dfiradapter"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/httpserver"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/ldapauth"
	"github.com/periapsis-im/periapsis/services/api/internal/mfapolicy"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
	"github.com/periapsis-im/periapsis/services/api/internal/notificationinbox"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentitybinding"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformldapauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformlocalaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoperations"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres"
	"github.com/periapsis-im/periapsis/services/api/internal/securityaudit"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/sla"
	"github.com/periapsis-im/periapsis/services/api/internal/telemetry"
	"github.com/periapsis-im/periapsis/services/api/internal/tenantsettings"
	"github.com/periapsis-im/periapsis/services/api/internal/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/ticketnumbering"
	"github.com/periapsis-im/periapsis/services/api/internal/webhookurlpolicy"
)

func main() {
	level, levelErr := parseLogLevel(os.Getenv("PERIAPSIS_LOG_LEVEL"))
	logger := slog.New(telemetry.NewTraceContextHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}),
	))
	if levelErr != nil {
		logger.Error("api configuration invalid", "error", levelErr)
		os.Exit(1)
	}
	if err := run(logger); err != nil {
		logger.Error("api stopped", "error", err)
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

func run(logger *slog.Logger) (returnErr error) {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	defer cfg.NotificationKeyring.Close()
	defer clearAuthenticationSourceConfig(&cfg)
	defer clearNotifierPreviewSourceConfig(&cfg)

	rootContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	telemetryConfig, err := telemetry.LoadConfig(cfg.Environment, "periapsis-api", cfg.Release)
	if err != nil {
		return errors.New("load API OpenTelemetry configuration")
	}
	telemetryRuntime, err := telemetry.Start(rootContext, telemetryConfig, logger)
	if err != nil {
		return errors.New("initialize API OpenTelemetry runtime")
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		flushErr := telemetryRuntime.ForceFlush(shutdownContext)
		shutdownErr := telemetryRuntime.Shutdown(shutdownContext)
		if flushErr != nil || shutdownErr != nil {
			returnErr = errors.Join(returnErr, errors.New("shutdown API OpenTelemetry runtime"))
		}
	}()

	pool, err := databasePool(
		rootContext, cfg.DatabaseURL, cfg.ReadinessTimeout, cfg.RequestTimeout,
		telemetryRuntime,
	)
	if err != nil {
		return err
	}
	defer pool.Close()

	cipher, err := authentication.NewSecretCipher(cfg.MasterKey)
	if err != nil {
		return errors.New("initialize protected authentication material")
	}
	authRepository := postgres.NewAuthenticationRepository(pool)
	authenticationService, err := authentication.NewService(authentication.ServiceOptions{
		Repository:                    authRepository,
		Passwords:                     authentication.PasswordManager{},
		Tokens:                        authentication.NewTokenGenerator(),
		TOTP:                          authentication.NewTOTPManager(),
		Cipher:                        cipher,
		RateLimitKeyMaterial:          cfg.MasterKey,
		BootstrapTokenDigest:          cfg.BootstrapTokenDigest,
		BootstrapEnrollmentTimeout:    cfg.BootstrapEnrollmentTimeout,
		MFAChallengeTimeout:           cfg.MFAChallengeTimeout,
		SessionIdleTimeout:            cfg.SessionIdleTimeout,
		SessionAbsoluteTimeout:        cfg.SessionAbsoluteTimeout,
		PasswordKDFConcurrency:        cfg.AuthKDFConcurrency,
		ProtectedConfigurationTimeout: cfg.ReadinessTimeout,
	})
	if err != nil {
		clearAuthenticationSourceConfig(&cfg)
		return errors.New("initialize authentication service")
	}
	apiRateLimiter, err := apiratelimit.New(
		postgres.NewAPIRateLimitRepository(pool), cfg.MasterKey, cfg.APIRateLimitPolicy,
	)
	if err != nil {
		clearAuthenticationSourceConfig(&cfg)
		return errors.New("initialize shared API rate limiter")
	}
	defer apiRateLimiter.Close()
	sessionRevalidator, err := federatedauth.NewSessionService(federatedauth.SessionServiceOptions{
		Sessions: postgres.NewFederatedAuthRepository(pool), Credentials: authenticationService,
		OperationTimeout: cfg.FederatedOperationTimeout,
	})
	if err != nil {
		clearAuthenticationSourceConfig(&cfg)
		return errors.New("initialize live session provenance service")
	}
	if err := authenticationService.BindFederatedSessionAuthority(&runtimeFederatedSessionAuthority{
		revalidator: sessionRevalidator,
	}); err != nil {
		clearAuthenticationSourceConfig(&cfg)
		return errors.New("bind live session provenance authority")
	}
	federatedComposition, err := newFederatedRuntimeComposition(pool, &cfg, authenticationService)
	if err != nil {
		clearAuthenticationSourceConfig(&cfg)
		return err
	}
	if !federatedComposition.enabled {
		logger.Warn(
			"federated browser authentication is disabled",
			"reason", "development public origin is not HTTPS",
		)
	}
	mfaService, mfaErr := newMFAApplication(pool, cfg)
	if mfaErr != nil {
		clearAuthenticationSourceConfig(&cfg)
		return mfaErr
	}
	platformLocalAccountRepository, err := postgres.NewPlatformLocalAccountRepository(pool)
	if err != nil {
		clearAuthenticationSourceConfig(&cfg)
		return errors.New("initialize platform local-account repository")
	}
	platformLocalAccountEnrollment, err := platformlocalaccount.NewEncryptedTOTPEnrollmentSecurity(
		authentication.NewTOTPManager(), cipher,
	)
	if err != nil {
		clearAuthenticationSourceConfig(&cfg)
		return errors.New("initialize platform local-account enrollment security")
	}
	platformLocalAccountService, err := platformlocalaccount.NewService(platformlocalaccount.Options{
		Repository: platformLocalAccountRepository, PasswordHasher: platformlocalaccount.Argon2idPasswordHasher{},
		TOTPEnrollment: platformLocalAccountEnrollment, CommandDigestKey: cfg.MasterKey,
		Now: time.Now,
	})
	if err != nil {
		return errors.New("initialize platform local-account service")
	}
	platformRepository := postgres.NewPlatformRepository(pool)
	platformService, err := platform.NewService(platformRepository)
	if err != nil {
		return errors.New("initialize platform service")
	}
	tenantLifecycleService, err := platform.NewTenantLifecycleService(platformRepository)
	if err != nil {
		return errors.New("initialize platform tenant lifecycle service")
	}
	platformTenantAccessService, err := platform.NewPlatformTenantAccessService(platformRepository)
	if err != nil {
		return errors.New("initialize platform tenant access service")
	}
	platformOperationsService, err := platformoperations.NewService(
		postgres.NewPlatformOperationsRepository(pool),
	)
	if err != nil {
		return errors.New("initialize platform operations service")
	}
	var platformIdentityProviderService httpserver.PlatformIdentityProviderService
	var platformIdentityAccountService httpserver.PlatformIdentityAccountService
	var platformIdentityBindingService httpserver.PlatformIdentityBindingService
	platformIdentityProviderEnabled, err := platformIdentityProviderAdministrationEnabled(&cfg)
	if err != nil {
		return err
	}
	if platformIdentityProviderEnabled {
		samlMetadataRetriever, retrieverErr := platformidentityprovider.NewHardenedSAMLMetadataRetriever(
			federatedComposition.httpClient,
		)
		if retrieverErr != nil {
			return errors.New("initialize protected SAML metadata retrieval")
		}
		platformIdentityProviderService, err = platformidentityprovider.NewService(
			postgres.NewPlatformIdentityProviderRepository(pool),
			cfg.IdentityKeyring,
			cfg.PublicOrigin,
			platformidentityprovider.SAMLAdministrationOptions{
				MetadataRetriever: samlMetadataRetriever,
				ValidateSPKey:     platformsamladapter.ValidateDirectSAMLSPKeyBundle,
				Now:               time.Now,
			},
		)
		if err != nil {
			return errors.New("initialize platform identity-provider service")
		}
		platformIdentityAccountRepository, repositoryErr := postgres.NewPlatformIdentityAccountRepository(pool)
		if repositoryErr != nil {
			return errors.New("initialize platform identity-account repository")
		}
		platformIdentityAccountService, err = platformidentityaccount.NewService(
			platformIdentityAccountRepository,
			cfg.IdentityKeyring,
		)
		if err != nil {
			return errors.New("initialize platform identity-account service")
		}
		platformIdentityBindingService, err = platformidentitybinding.NewService(
			postgres.NewPlatformIdentityBindingRepository(pool),
		)
		if err != nil {
			return errors.New("initialize platform identity-provider tenant-binding service")
		}
	} else {
		logger.Warn(
			"platform identity-provider administration is disabled",
			"reason", "development public origin is not HTTPS",
		)
	}
	authorizationRepository := postgres.NewAuthorizationRepository(pool)
	authorizationService, err := authorization.NewService(authorizationRepository)
	if err != nil {
		return errors.New("initialize tenant authorization service")
	}
	tenantSettingsService, err := tenantsettings.NewService(
		postgres.NewTenantSettingsRepository(pool),
		authorizationService,
	)
	if err != nil {
		return errors.New("initialize tenant settings service")
	}
	ticketNumberingService, err := ticketnumbering.NewService(
		postgres.NewTicketNumberingRepository(pool),
		authorizationService,
	)
	if err != nil {
		return errors.New("initialize ticket numbering service")
	}
	webhookURLPolicyService, err := webhookurlpolicy.NewService(
		postgres.NewWebhookURLPolicyRepository(pool),
		authorizationService,
	)
	if err != nil {
		return errors.New("initialize webhook URL policy service")
	}
	mfaPolicyService, err := mfapolicy.NewService(
		postgres.NewMFAPolicyRepository(pool),
		authorizationService,
	)
	if err != nil {
		return errors.New("initialize MFA policy administration service")
	}
	auditService, err := securityaudit.NewService(
		postgres.NewSecurityAuditRepository(pool),
		authorizationRepository,
	)
	if err != nil {
		return errors.New("initialize security-audit service")
	}
	operatorTeamService, err := operatorteam.NewService(postgres.NewOperatorTeamRepository(pool))
	if err != nil {
		return errors.New("initialize operator team service")
	}
	serviceAccountService, err := serviceaccount.NewService(
		postgres.NewServiceAccountRepository(pool),
		cfg.CredentialKeyring,
	)
	if err != nil {
		return errors.New("initialize service-account service")
	}
	alertService, err := alert.NewService(postgres.NewAlertRepository(pool), cfg.CredentialKeyring)
	if err != nil {
		return errors.New("initialize Alert service")
	}
	ticketingRepository := postgres.NewTicketingRepository(pool)
	ticketingService, err := ticketing.NewService(ticketingRepository, time.Now)
	if err != nil {
		return errors.New("initialize ticketing service")
	}
	workflowAdministrationService, err := ticketing.NewWorkflowAdminService(ticketingRepository)
	if err != nil {
		return errors.New("initialize workflow administration service")
	}
	savedViewService, err := ticketing.NewSavedViewService(ticketingRepository)
	if err != nil {
		return errors.New("initialize saved ticket view service")
	}
	ticketBulkService, err := ticketing.NewTicketBulkService(ticketingRepository, time.Now)
	if err != nil {
		return errors.New("initialize ticket bulk service")
	}
	slaService, err := sla.NewService(postgres.NewSLARepository(pool), time.Now)
	if err != nil {
		return errors.New("initialize SLA service")
	}
	contactService, err := contacts.NewService(postgres.NewContactsRepository(pool), time.Now)
	if err != nil {
		return errors.New("initialize customer-contact service")
	}
	customFieldService, err := customfields.NewService(postgres.NewCustomFieldRepository(pool))
	if err != nil {
		return errors.New("initialize custom-field service")
	}
	customFieldImportService, err := customfieldimport.NewService(
		postgres.NewCustomFieldImportRepository(pool), time.Now,
	)
	if err != nil {
		return errors.New("initialize custom-field import service")
	}
	dfirConfig, err := dfiradapter.LoadConfig(cfg.Environment)
	if err != nil {
		return errors.New("load DFIR storage and scanner configuration")
	}
	dfirStorage, err := dfiradapter.NewS3(dfirConfig.Storage)
	if err != nil {
		return errors.New("initialize DFIR object storage")
	}
	auditOperationsService, err := auditoperations.NewService(
		postgres.NewAuditOperationsRepository(pool),
		authorizationRepository,
		dfirStorage,
	)
	if err != nil {
		return errors.New("initialize audit export and retention service")
	}
	asyncExportService, err := ticketing.NewAsyncExportServiceWithDownloadStorage(
		ticketingRepository,
		time.Now,
		nil,
		dfirStorage,
	)
	if err != nil {
		return errors.New("initialize asynchronous ticket export service")
	}
	dfirScanner, err := dfiradapter.NewClamAV(dfirConfig.Scanner)
	if err != nil {
		return errors.New("initialize DFIR malware scanner")
	}
	dfirRepository := postgres.NewDFIRRepository(pool)
	dfirService, err := dfir.NewService(
		dfirRepository,
		dfirStorage,
		dfirScanner,
		dfir.ServiceConfig{
			Bucket:           dfirConfig.Storage.Bucket(),
			MaximumSize:      dfirConfig.Storage.MaximumObjectBytes(),
			Clock:            time.Now,
			PortalAuthorizer: dfir.NewContactPortalAuthorizer(contactService),
		},
	)
	if err != nil {
		return errors.New("initialize DFIR service")
	}
	alertInvestigationService, err := dfir.NewAlertInvestigationService(
		dfirRepository,
		dfir.AlertInvestigationServiceConfig{Bucket: dfirConfig.Storage.Bucket(), Clock: time.Now},
	)
	if err != nil {
		return errors.New("initialize Alert investigation service")
	}
	notificationPreviewer, err := notification.NewHTTPPreviewer(
		cfg.NotifierInternalURL,
		cfg.NotifierPreviewToken,
		cfg.RequestTimeout,
	)
	if err != nil {
		return errors.New("initialize notification template preview client")
	}
	defer notificationPreviewer.Close()
	clearNotifierPreviewSourceConfig(&cfg)
	notificationRepository := postgres.NewNotificationRepository(pool, cfg.NotificationKeyring)
	notificationService, err := notification.NewService(
		notificationRepository,
		cfg.NotificationKeyring,
		notificationPreviewer,
		notification.ServiceOptions{AllowPlainLocal: cfg.WebhookAllowPlainLocal},
	)
	if err != nil {
		return errors.New("initialize notification administration service")
	}
	notificationInboxService, err := notificationinbox.NewService(
		postgres.NewNotificationInboxRepository(pool),
		time.Now,
	)
	if err != nil {
		return errors.New("initialize notification inbox service")
	}
	credentialKeyringReadiness, err := serviceaccount.NewKeyringReadinessVerifier(
		postgres.NewAPIKeyVersionInventory(pool),
		cfg.CredentialKeyring,
	)
	if err != nil {
		return errors.New("initialize API credential keyring readiness")
	}
	ldapClient, err := ldapclient.New(ldapclient.Options{
		Resolver:             net.DefaultResolver,
		Dialer:               &net.Dialer{},
		PrivateEgressCIDRs:   cfg.LDAPPrivateEgressCIDRs,
		AllowedStartTLSPorts: cfg.LDAPAllowedStartTLSPorts,
		AllowedLDAPSPorts:    cfg.LDAPAllowedLDAPSPorts,
		MaxConcurrent:        cfg.LDAPMaxConcurrent,
	})
	if err != nil {
		return errors.New("initialize LDAP diagnostic client")
	}
	if service, ok := platformIdentityProviderService.(*platformidentityprovider.Service); ok {
		if err := service.ConfigureLDAPDiagnostics(ldapClient); err != nil {
			return errors.New("initialize platform LDAP diagnostic service")
		}
	}
	identityProviderRepository := postgres.NewIdentityProviderRepository(pool)
	identityProviderService, err := identityprovider.NewService(
		identityProviderRepository,
		cfg.IdentityKeyring,
		ldapClient,
	)
	if err != nil {
		return errors.New("initialize identity-provider service")
	}
	ldapAuthenticationService, err := ldapauth.New(ldapauth.Options{
		Repository: postgres.NewLDAPAuthenticationRepository(pool), Directory: ldapClient,
		Keyring: cfg.IdentityKeyring, Credentials: authenticationService,
		RateDigestKey: cfg.MasterKey, OperationTimeout: cfg.RequestTimeout,
	})
	if err != nil {
		return errors.New("initialize interactive LDAP authentication service")
	}
	platformLDAPAuthenticationService, err := platformldapauth.New(platformldapauth.Options{
		Repository: postgres.NewFederatedAuthRepository(pool), Directory: ldapClient,
		Keyring: cfg.IdentityKeyring, TOTPVerifier: authenticationService,
		Credentials: authenticationService, RateDigestKey: cfg.MasterKey,
		OperationTimeout: cfg.RequestTimeout,
	})
	clearAuthenticationSourceConfig(&cfg)
	if err != nil {
		return errors.New("initialize platform LDAP authentication service")
	}
	var tenantFederationService httpserver.TenantFederationAdministrationService
	if strings.HasPrefix(cfg.PublicOrigin, "https://") {
		service, serviceErr := identityprovider.NewFederationServiceWithOIDCTrust(
			identityProviderRepository,
			identityProviderRepository,
			cfg.IdentityKeyring,
			cfg.PublicOrigin,
			federatedComposition.oidcTrust,
		)
		if serviceErr != nil {
			return errors.New("initialize tenant federation administration service")
		}
		samlMetadataRetriever, retrieverErr := platformidentityprovider.NewHardenedSAMLMetadataRetriever(
			federatedComposition.httpClient,
		)
		if retrieverErr != nil {
			return errors.New("initialize tenant SAML metadata retrieval")
		}
		if configureErr := service.ConfigureFederationSAMLAdministration(
			identityProviderRepository,
			identityprovider.FederationSAMLAdministrationOptions{
				MetadataRetriever: samlMetadataRetriever,
				GenerateSPKey:     identityprovider.GenerateFederationSAMLSPCredential,
				ValidateSPKey:     platformsamladapter.ValidateSAMLSPKeyBundle,
			},
		); configureErr != nil {
			return errors.New("initialize tenant SAML administration service")
		}
		tenantFederationService = service
	}
	identityKeyringReadiness, err := identityprovider.NewKeyringReadinessVerifier(
		postgres.NewIdentityKeyringEvidenceVerifier(pool),
		cfg.IdentityKeyring,
	)
	if err != nil {
		return errors.New("initialize identity keyring readiness")
	}
	notificationKeyringReadiness, err := notification.NewKeyringReadinessVerifier(
		postgres.NewNotificationKeyVersionVerifier(pool),
		cfg.NotificationKeyring,
	)
	if err != nil {
		return errors.New("initialize notification keyring readiness")
	}
	readinessChecker := &protectedConfigReadiness{
		database:              postgres.NewHealthChecker(pool),
		authentication:        authenticationService,
		credentialKeyring:     credentialKeyringReadiness,
		dfirObjectStorage:     dfirStorage,
		dfirMalwareScanner:    dfirScanner,
		identityKeyring:       identityKeyringReadiness,
		notificationKeyring:   notificationKeyringReadiness,
		federated:             federatedComposition.readiness,
		ticketOperations:      ticketingRepository,
		platformLocalAccounts: platformLocalAccountRepository,
	}
	preflightContext, cancelPreflight := context.WithTimeout(context.Background(), cfg.ReadinessTimeout)
	_ = readinessChecker.Check(preflightContext)
	cancelPreflight()
	applicationOptions := bindIdentityProviderServices(
		httpserver.ApplicationOptions{
			Alerts:                     alertService,
			AsyncExports:               asyncExportService,
			Audit:                      auditService,
			AuditOperations:            auditOperationsService,
			Authentication:             authenticationService,
			SessionLogout:              federatedComposition.sessionLogout,
			Authorization:              authorizationService,
			Contacts:                   contactService,
			CustomFields:               customFieldService,
			CustomFieldImports:         customFieldImportService,
			DFIR:                       dfirService,
			AlertInvestigation:         alertInvestigationService,
			Environment:                cfg.Environment,
			FederatedBrowser:           federatedComposition.browser,
			LDAPAuthentication:         ldapAuthenticationService,
			MFA:                        mfaService,
			MFAPolicies:                mfaPolicyService,
			Notifications:              notificationService,
			NotificationInbox:          notificationInboxService,
			OperatorTeams:              operatorTeamService,
			Platform:                   platformService,
			PlatformTenantAccess:       platformTenantAccessService,
			PlatformOIDCBrowser:        federatedComposition.platformOIDCBrowser,
			PlatformSAMLBrowser:        federatedComposition.platformSAMLBrowser,
			PlatformSAMLContinuation:   federatedComposition.platformSAMLContinuation,
			PlatformIdentityAccounts:   platformIdentityAccountService,
			PlatformIdentityBindings:   platformIdentityBindingService,
			PlatformIdentityProviders:  platformIdentityProviderService,
			PlatformLDAPAuthentication: platformLDAPAuthenticationService,
			PlatformLocalAccounts:      platformLocalAccountService,
			PlatformOperations:         platformOperationsService,
			PublicOrigin:               cfg.PublicOrigin,
			RequestTimeout:             cfg.RequestTimeout,
			ServiceAccounts:            serviceAccountService,
			SLA:                        slaService,
			SavedViews:                 savedViewService,
			TenantLifecycle:            tenantLifecycleService,
			TenantSettings:             tenantSettingsService,
			TicketNumbering:            ticketNumberingService,
			WebhookURLPolicy:           webhookURLPolicyService,
			TenantFederation:           tenantFederationService,
			Ticketing:                  ticketingService,
			TicketBulk:                 ticketBulkService,
			WorkflowAdministration:     workflowAdministrationService,
			TrustedProxyCIDRs:          cfg.TrustedProxyCIDRs,
		},
		identityProviderService,
	)
	handler, err := httpserver.NewApplicationHandler(
		readinessChecker,
		logger, cfg.Release, cfg.ReadinessTimeout,
		applicationOptions,
	)
	if err != nil {
		return errors.New("initialize HTTP application")
	}
	metrics := telemetry.NewMetrics()
	server := &http.Server{
		Addr: cfg.Address,
		Handler: httpserver.Router(
			handler,
			logger,
			cfg.DocsEnabled,
			httpserver.RouterObservability{
				Metrics: metrics, Tracing: telemetryRuntime, RateLimiter: apiRateLimiter,
			},
		),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("api started", "address", cfg.Address, "environment", cfg.Environment, "release", cfg.Release)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-rootContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		err := <-serverErrors
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		logger.Info("api stopped gracefully")
		return nil
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// platformIdentityProviderAdministrationEnabled mirrors the federated browser
// boundary: direct local HTTP may keep the rest of development available, but
// the platform provider surface remains explicitly unavailable because its
// persisted redirect and ACS endpoints are HTTPS-only trust anchors.
func platformIdentityProviderAdministrationEnabled(cfg *config.Config) (bool, error) {
	if cfg == nil {
		return false, errors.New("platform identity-provider configuration is required")
	}
	if strings.HasPrefix(cfg.PublicOrigin, "https://") {
		return true, nil
	}
	if cfg.Environment == "production" {
		return false, errors.New("platform identity-provider administration requires an HTTPS public origin")
	}
	return false, nil
}

// bindIdentityProviderServices keeps the provider inventory and the LDAP
// administration surface on the same concrete, fully wired service. Keeping
// this binding explicit prevents startup from silently omitting the newer
// administration capability while the legacy provider surface still compiles.
func bindIdentityProviderServices(
	options httpserver.ApplicationOptions,
	service *identityprovider.Service,
) httpserver.ApplicationOptions {
	options.IdentityProviders = service
	options.LDAPAdministration = service
	return options
}

func clearAuthenticationSourceConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	clear(cfg.MasterKey)
	clear(cfg.BootstrapTokenDigest)
	cfg.MasterKey = nil
	cfg.BootstrapTokenDigest = nil
}

func clearNotifierPreviewSourceConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	clear(cfg.NotifierPreviewToken)
	cfg.NotifierPreviewToken = nil
}

type protectedConfigReadiness struct {
	database              httpserver.ReadinessChecker
	authentication        protectedConfigurationVerifier
	credentialKeyring     credentialKeyringVerifier
	dfirObjectStorage     dependencyVerifier
	dfirMalwareScanner    dependencyVerifier
	identityKeyring       identityKeyringVerifier
	notificationKeyring   notificationKeyringVerifier
	federated             federatedReadinessVerifier
	ticketOperations      ticketOperationsReadinessVerifier
	platformLocalAccounts platformLocalAccountReadinessVerifier
	mu                    sync.Mutex
	cached                []postgres.DependencyCheck
	checkedAt             time.Time
}

const protectedReadinessCacheInterval = time.Second

type protectedConfigurationVerifier interface {
	VerifyProtectedConfiguration(context.Context) error
	InvalidateProtectedConfiguration()
}

type credentialKeyringVerifier interface {
	VerifyLiveKeyVersions(context.Context) error
}

type identityKeyringVerifier interface {
	Verify(context.Context) error
}

type notificationKeyringVerifier interface {
	Verify(context.Context) error
}

type dependencyVerifier interface {
	Check(context.Context) error
}

type ticketOperationsReadinessVerifier interface {
	ReadyTicketOperations(context.Context) error
}

type platformLocalAccountReadinessVerifier interface {
	ReadyPlatformLocalAccounts(context.Context) error
}

func (c *protectedConfigReadiness) Check(ctx context.Context) []postgres.DependencyCheck {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !c.checkedAt.IsZero() && !now.Before(c.checkedAt) &&
		now.Sub(c.checkedAt) < protectedReadinessCacheInterval {
		return append([]postgres.DependencyCheck(nil), c.cached...)
	}
	if ctx.Err() != nil {
		if c.authentication != nil {
			c.authentication.InvalidateProtectedConfiguration()
		}
		return []postgres.DependencyCheck{{Name: "readiness_probe", Ready: false}}
	}
	checks := c.database.Check(ctx)
	databaseReady := len(checks) > 0
	for _, check := range checks {
		if !check.Ready {
			databaseReady = false
			break
		}
	}
	authenticationReady := false
	credentialKeyringReady := false
	identityKeyringReady := false
	notificationKeyringReady := false
	federatedReady := c.federated == nil
	dfirObjectStorageReady := false
	dfirMalwareScannerReady := false
	ticketOperationsReady := false
	platformLocalAccountsReady := false
	authenticationStartedAt := time.Now()
	if databaseReady && c.authentication != nil {
		if err := c.authentication.VerifyProtectedConfiguration(ctx); err == nil {
			authenticationReady = true
		}
	}
	authenticationLatency := time.Since(authenticationStartedAt)
	credentialKeyringStartedAt := time.Now()
	if databaseReady && c.credentialKeyring != nil {
		if err := c.credentialKeyring.VerifyLiveKeyVersions(ctx); err == nil {
			credentialKeyringReady = true
		}
	}
	credentialKeyringLatency := time.Since(credentialKeyringStartedAt)
	identityKeyringStartedAt := time.Now()
	if databaseReady && c.identityKeyring != nil {
		if err := c.identityKeyring.Verify(ctx); err == nil {
			identityKeyringReady = true
		}
	}
	identityKeyringLatency := time.Since(identityKeyringStartedAt)
	notificationKeyringStartedAt := time.Now()
	if databaseReady && c.notificationKeyring != nil {
		if err := c.notificationKeyring.Verify(ctx); err == nil {
			notificationKeyringReady = true
		}
	}
	notificationKeyringLatency := time.Since(notificationKeyringStartedAt)
	federatedStartedAt := time.Now()
	if databaseReady && c.federated != nil {
		if err := c.federated.Ready(ctx); err == nil {
			federatedReady = true
		}
	}
	federatedLatency := time.Since(federatedStartedAt)
	dfirObjectStorageStartedAt := time.Now()
	if databaseReady && c.dfirObjectStorage != nil {
		if err := c.dfirObjectStorage.Check(ctx); err == nil {
			dfirObjectStorageReady = true
		}
	}
	dfirObjectStorageLatency := time.Since(dfirObjectStorageStartedAt)
	dfirMalwareScannerStartedAt := time.Now()
	if databaseReady && c.dfirMalwareScanner != nil {
		if err := c.dfirMalwareScanner.Check(ctx); err == nil {
			dfirMalwareScannerReady = true
		}
	}
	dfirMalwareScannerLatency := time.Since(dfirMalwareScannerStartedAt)
	ticketOperationsStartedAt := time.Now()
	if databaseReady && !runtimeDependencyIsNil(c.ticketOperations) {
		if err := c.ticketOperations.ReadyTicketOperations(ctx); err == nil {
			ticketOperationsReady = true
		}
	}
	ticketOperationsLatency := time.Since(ticketOperationsStartedAt)
	platformLocalAccountsStartedAt := time.Now()
	if databaseReady && !runtimeDependencyIsNil(c.platformLocalAccounts) {
		if err := c.platformLocalAccounts.ReadyPlatformLocalAccounts(ctx); err == nil {
			platformLocalAccountsReady = true
		}
	}
	platformLocalAccountsLatency := time.Since(platformLocalAccountsStartedAt)
	if c.authentication != nil && (!authenticationReady || !credentialKeyringReady || !identityKeyringReady) {
		c.authentication.InvalidateProtectedConfiguration()
	}
	checks = append(checks, postgres.DependencyCheck{
		Name: "protected_authentication_configuration", Ready: authenticationReady, Latency: authenticationLatency,
	}, postgres.DependencyCheck{
		Name: "api_credential_keyring", Ready: credentialKeyringReady, Latency: credentialKeyringLatency,
	}, postgres.DependencyCheck{
		Name: "identity_keyring", Ready: identityKeyringReady, Latency: identityKeyringLatency,
	}, postgres.DependencyCheck{
		Name: "notification_keyring", Ready: notificationKeyringReady, Latency: notificationKeyringLatency,
	}, postgres.DependencyCheck{
		Name: "dfir_object_storage", Ready: dfirObjectStorageReady, Latency: dfirObjectStorageLatency,
	}, postgres.DependencyCheck{
		Name: "dfir_malware_scanner", Ready: dfirMalwareScannerReady, Latency: dfirMalwareScannerLatency,
	}, postgres.DependencyCheck{
		Name: "ticket_operations", Ready: ticketOperationsReady, Latency: ticketOperationsLatency,
	}, postgres.DependencyCheck{
		Name: "platform_local_accounts", Ready: platformLocalAccountsReady, Latency: platformLocalAccountsLatency,
	})
	if c.federated != nil {
		checks = append(checks, postgres.DependencyCheck{
			Name: "federated_authentication", Ready: federatedReady, Latency: federatedLatency,
		})
	}
	c.cached = append(c.cached[:0], checks...)
	c.checkedAt = time.Now()
	return append([]postgres.DependencyCheck(nil), checks...)
}

func databasePool(
	ctx context.Context,
	databaseURL string,
	readinessTimeout time.Duration,
	requestTimeout time.Duration,
	telemetryRuntime *telemetry.Runtime,
) (*pgxpool.Pool, error) {
	if databaseURL == "" {
		return nil, errors.New("database configuration is required")
	}

	poolConfig, err := databasePoolConfig(databaseURL, requestTimeout)
	if err != nil {
		return nil, err
	}
	if err := telemetryRuntime.InstrumentPGX(poolConfig); err != nil {
		return nil, errors.New("instrument API database pool")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("create database pool")
	}
	validationContext, cancel := context.WithTimeout(ctx, readinessTimeout)
	defer cancel()
	if err := validateRuntimeDatabaseRole(validationContext, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func databasePoolConfig(databaseURL string, requestTimeout time.Duration) (*pgxpool.Config, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("parse database configuration")
	}
	pinDatabaseRuntimeParam(poolConfig.ConnConfig.RuntimeParams, "application_name", "periapsis-api")
	pinDatabaseRuntimeParam(poolConfig.ConnConfig.RuntimeParams, "timezone", "UTC")
	pinDatabaseRuntimeParam(
		poolConfig.ConnConfig.RuntimeParams,
		"statement_timeout",
		strconv.FormatInt(requestTimeout.Milliseconds(), 10),
	)
	pinDatabaseRuntimeParam(
		poolConfig.ConnConfig.RuntimeParams,
		"idle_in_transaction_session_timeout",
		strconv.FormatInt((2*requestTimeout).Milliseconds(), 10),
	)
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

func validateRuntimeDatabaseRole(ctx context.Context, pool *pgxpool.Pool) error {
	var currentRole string
	var superuser, createDB, createRole, replication, bypassRLS, apiMember bool
	var incompatibleMemberships []string
	err := pool.QueryRow(ctx, `
		SELECT current_user, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
		       role.rolreplication, role.rolbypassrls,
		       pg_has_role(current_user, 'periapsis_api', 'member'),
		       ARRAY(
		         SELECT candidate.rolname
		         FROM pg_catalog.pg_roles AS candidate
		         WHERE candidate.rolname <> current_user
		           AND candidate.rolname <> 'periapsis_api'
		           AND pg_has_role(current_user, candidate.rolname, 'member')
		         ORDER BY candidate.rolname
		       )::text[]
		FROM pg_catalog.pg_roles AS role
		WHERE role.rolname = current_user
	`).Scan(
		&currentRole, &superuser, &createDB, &createRole, &replication,
		&bypassRLS, &apiMember, &incompatibleMemberships,
	)
	if err != nil {
		return errors.New("validate API database role")
	}
	if err := validateRuntimeRoleMetadata(runtimeRoleMetadata{
		name: currentRole, superuser: superuser, createDB: createDB,
		createRole: createRole, replication: replication, bypassRLS: bypassRLS,
		apiMember: apiMember, incompatibleMemberships: incompatibleMemberships,
	}); err != nil {
		return errors.New("database connection is not a least-privileged API role")
	}
	return nil
}

type runtimeRoleMetadata struct {
	name                    string
	superuser               bool
	createDB                bool
	createRole              bool
	replication             bool
	bypassRLS               bool
	apiMember               bool
	incompatibleMemberships []string
}

func validateRuntimeRoleMetadata(role runtimeRoleMetadata) error {
	if role.name == "" || role.superuser || role.createDB || role.createRole ||
		role.replication || role.bypassRLS || !role.apiMember || len(role.incompatibleMemberships) != 0 {
		return errors.New("runtime role has incompatible authority")
	}
	return nil
}
