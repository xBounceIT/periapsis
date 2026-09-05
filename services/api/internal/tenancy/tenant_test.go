package tenancy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type capturingRepository struct {
	created Tenant
}

func (r *capturingRepository) Create(_ context.Context, tenant Tenant) (Tenant, error) {
	r.created = tenant
	return tenant, nil
}

func (*capturingRepository) Get(context.Context, uuid.UUID) (Tenant, error) {
	return Tenant{}, nil
}

func (*capturingRepository) List(context.Context, int, *uuid.UUID) ([]Tenant, error) {
	return nil, nil
}

func TestCreateNormalizesAndValidatesTenant(t *testing.T) {
	repository := &capturingRepository{}
	createdAt := time.Date(2026, time.August, 23, 10, 0, 0, 0, time.FixedZone("local", 7200))
	identifier := uuid.Must(uuid.NewV7())
	service := NewService(repository, func() (uuid.UUID, error) {
		return identifier, nil
	}, func() time.Time {
		return createdAt
	})

	tenant, err := service.Create(context.Background(), CreateInput{
		Slug:     "  Acme-SOC ",
		Name:     " Acme Corporation ",
		Timezone: "Europe/Rome",
		Locale:   "it-IT",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if tenant.Slug != "acme-soc" || tenant.Name != "Acme Corporation" {
		t.Fatalf("tenant = %#v", tenant)
	}
	if tenant.CreatedAt.Location() != time.UTC {
		t.Fatalf("CreatedAt location = %v, want UTC", tenant.CreatedAt.Location())
	}
	if repository.created.ID != identifier {
		t.Fatal("repository did not receive the generated identifier")
	}
}

func TestCreateRejectsInvalidTimezoneBeforePersistence(t *testing.T) {
	repository := &capturingRepository{}
	service := NewService(repository, NewUUIDv7, time.Now)

	_, err := service.Create(context.Background(), CreateInput{
		Slug:     "globex",
		Name:     "Globex",
		Timezone: "Mars/Olympus",
	})
	if err == nil {
		t.Fatal("Create() accepted an invalid timezone")
	}
	if repository.created.ID != uuid.Nil {
		t.Fatal("invalid tenant reached the repository")
	}
}

func TestCreateRejectsNonV7Identifier(t *testing.T) {
	service := NewService(&capturingRepository{}, func() (uuid.UUID, error) {
		return uuid.New(), nil
	}, time.Now)

	_, err := service.Create(context.Background(), CreateInput{
		Slug: "globex",
		Name: "Globex",
	})
	if err == nil {
		t.Fatal("Create() accepted a non-v7 identifier")
	}
}
