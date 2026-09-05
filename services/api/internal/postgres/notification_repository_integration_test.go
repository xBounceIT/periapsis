package postgres

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
)

func TestNotificationRepositoryLiveTenantIsolationAndReplay(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("PERIAPSIS_NOTIFICATION_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PERIAPSIS_NOTIFICATION_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect notification database: %v", err)
	}
	defer pool.Close()
	keyring, err := notification.NewKeyring(1, map[int16][]byte{
		1: bytes.Repeat([]byte{0x61}, 32),
	})
	if err != nil {
		t.Fatalf("construct notification keyring: %v", err)
	}
	defer keyring.Close()
	repository := NewNotificationRepository(pool, keyring)
	templateID := uuid.Must(uuid.NewV7())
	when := time.Now().UTC().Truncate(time.Microsecond)
	mutation := notification.MutationParams{
		Human: notification.HumanParams{
			TenantID:     uuid.MustParse("01993ea0-0000-7000-8000-000000000001"),
			MembershipID: uuid.MustParse("01993ea0-0000-7000-8000-000000000203"),
			Actor: authorization.Actor{
				UserID:               uuid.MustParse("01993ea0-0000-7000-8000-000000000103"),
				ActiveTenantID:       uuid.MustParse("01993ea0-0000-7000-8000-000000000001"),
				AuthenticationMethod: "totp",
			},
		},
		Audit: authorization.AuditContext{
			RequestID:     uuid.Must(uuid.NewV7()),
			CorrelationID: uuid.Must(uuid.NewV7()),
			RemoteAddress: netip.MustParseAddr("192.0.2.119"),
			UserAgent:     "Periapsis notification repository integration test",
		},
		OccurredAt:     when,
		IdempotencyKey: "notification-integration-" + templateID.String(),
	}
	plainText := "Notification integration proof"
	fields := notification.TemplateFields{
		Key:  "integration." + strings.ReplaceAll(templateID.String(), "-", ""),
		Name: "Notification integration proof", Language: "en",
		Subject:   "Notification integration proof",
		HTML:      "<p>Notification integration proof</p>",
		PlainText: &plainText, SampleData: map[string]any{},
	}
	created, err := repository.CreateTemplate(ctx, notification.CreateTemplateParams{
		Mutation: mutation, TemplateID: templateID, Fields: fields,
	})
	if err != nil {
		t.Fatalf("CreateTemplate() error = %v", err)
	}
	if created.Replayed || created.Value.ID != templateID || created.Value.TenantID != mutation.Human.TenantID || created.Value.Version != 1 {
		t.Fatalf("CreateTemplate() = %#v", created)
	}
	replayed, err := repository.CreateTemplate(ctx, notification.CreateTemplateParams{
		Mutation: mutation, TemplateID: templateID, Fields: fields,
	})
	if err != nil || !replayed.Replayed || replayed.Value.ID != templateID {
		t.Fatalf("CreateTemplate() replay = %#v, %v", replayed, err)
	}
	conflictFields := fields
	conflictFields.Name = "Conflicting replay"
	_, err = repository.CreateTemplate(ctx, notification.CreateTemplateParams{
		Mutation: mutation, TemplateID: templateID, Fields: conflictFields,
	})
	if !errors.Is(err, notification.ErrConflict) {
		t.Fatalf("conflicting CreateTemplate() error = %v, want conflict", err)
	}

	got, err := repository.GetTemplate(ctx, notification.GetTemplateParams{
		Human: mutation.Human, TemplateID: templateID,
	})
	if err != nil || got.ID != templateID || got.Name != fields.Name {
		t.Fatalf("GetTemplate() = %#v, %v", got, err)
	}
	foreign := mutation.Human
	foreign.TenantID = uuid.MustParse("01993ea0-0000-7000-8000-000000000002")
	foreign.MembershipID = uuid.MustParse("01993ea0-0000-7000-8000-000000000204")
	foreign.Actor.UserID = uuid.MustParse("01993ea0-0000-7000-8000-000000000104")
	foreign.Actor.ActiveTenantID = foreign.TenantID
	_, err = repository.GetTemplate(ctx, notification.GetTemplateParams{
		Human: foreign, TemplateID: templateID,
	})
	if !errors.Is(err, notification.ErrNotFound) {
		t.Fatalf("cross-tenant GetTemplate() error = %v, want not found", err)
	}

	configurationID := uuid.Must(uuid.NewV7())
	secretID := uuid.Must(uuid.NewV7())
	secretContext := notification.SecretContext{
		TenantID: &mutation.Human.TenantID, SecretID: secretID,
		SecretVersion: 1, Kind: notification.SecretKindSMTPPassword,
	}
	envelope, err := keyring.Protect(secretContext, []byte("integration-password"))
	if err != nil {
		t.Fatalf("protect SMTP password: %v", err)
	}
	username := "integration"
	smtpMutation := mutation
	smtpMutation.IdempotencyKey = "smtp-integration-" + configurationID.String()
	smtpMutation.Audit.RequestID = uuid.Must(uuid.NewV7())
	configured, err := repository.VersionTenantSMTP(ctx, notification.VersionTenantSMTPParams{
		Mutation: smtpMutation, ConfigurationID: configurationID,
		Write: notification.SMTPPersistedWrite{
			Name: "Integration SMTP", Host: "smtp.example.invalid", Port: 465,
			Security: notification.SMTPTLS, Username: &username,
			Password: &notification.ProtectedSecret{
				ID: secretID, Version: 1, Kind: notification.SecretKindSMTPPassword,
				Envelope: envelope,
			},
			FromName: "Periapsis", FromEmail: "periapsis@example.invalid",
			TimeoutMS: 10_000, MaximumConnections: 1,
			MaximumMessagesPerConnection: 100, RateLimitPerSecond: 10,
			Enabled: true,
		},
	})
	if err != nil || configured.Replayed || configured.Value.ID != configurationID || configured.Value.Version != 1 || !configured.Value.PasswordConfigured {
		t.Fatalf("VersionTenantSMTP() = %#v, %v", configured, err)
	}
	loadedSMTP, err := repository.GetTenantSMTP(ctx, notification.GetTenantSMTPParams{Human: mutation.Human})
	if err != nil || loadedSMTP.ID != configurationID || loadedSMTP.Version != 1 || !loadedSMTP.PasswordConfigured {
		t.Fatalf("GetTenantSMTP() = %#v, %v", loadedSMTP, err)
	}
	recipient := "operator@example.invalid"
	deliveryID := uuid.Must(uuid.NewV7())
	testMutation := mutation
	testMutation.IdempotencyKey = "smtp-delivery-integration-" + deliveryID.String()
	testMutation.Audit.RequestID = uuid.Must(uuid.NewV7())
	preflight, err := repository.TestTenantSMTP(ctx, notification.TestTenantSMTPParams{
		Mutation: testMutation, ConfigurationVersion: 1,
		DeliveryID: &deliveryID, Recipient: &recipient,
		Reason: "Notification delivery lifecycle integration proof",
	})
	if err != nil || preflight.Replayed || preflight.Value.ConfigurationID != configurationID ||
		preflight.Value.ConfigurationVersion != 1 ||
		preflight.Value.ConfigurationScope != notification.SMTPConfigurationTenant ||
		preflight.Value.QueuedDeliveryID == nil || *preflight.Value.QueuedDeliveryID != deliveryID {
		t.Fatalf("TestTenantSMTP() = %#v, %v", preflight, err)
	}
	delivery, err := repository.GetDelivery(ctx, notification.GetDeliveryParams{
		Human: mutation.Human, DeliveryID: deliveryID,
	})
	if err != nil || delivery.ID != deliveryID || delivery.Status != notification.DeliveryQueued || delivery.SMTPConfigurationScope == nil || *delivery.SMTPConfigurationScope != "tenant" {
		t.Fatalf("GetDelivery() = %#v, %v", delivery, err)
	}
}
