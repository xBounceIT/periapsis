package ticketing

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	savedViewCommandDomain     = "periapsis.ticketing.saved-view.command.v1"
	savedViewIdempotencyDomain = "periapsis.ticketing.saved-view.idempotency.v1\x00"
	maximumSavedViewSpecBytes  = 256 * 1024
)

type savedViewCommandEnvelope struct {
	Domain            string `json:"domain"`
	Action            string `json:"action"`
	TenantID          string `json:"tenantId"`
	OwnerMembershipID string `json:"ownerMembershipId"`
	Kind              string `json:"kind"`
	ViewID            string `json:"viewId,omitempty"`
	ExpectedRevision  uint64 `json:"expectedRevision"`
	Name              string `json:"name,omitempty"`
	SpecDigest        string `json:"specDigest,omitempty"`
}

type savedViewSpecCanonical struct {
	Version int                        `json:"version"`
	Filters savedViewFiltersCanonical  `json:"filters"`
	Sort    savedViewSortCanonical     `json:"sort"`
	Columns []savedViewColumnCanonical `json:"columns"`
}

type savedViewFiltersCanonical struct {
	States          []string                         `json:"states"`
	Severities      []string                         `json:"severities"`
	Priorities      []string                         `json:"priorities"`
	AssignedTeamID  string                           `json:"assignedTeamId,omitempty"`
	AssigneeUserID  string                           `json:"assigneeUserId,omitempty"`
	ClaimedBy       string                           `json:"claimedBy,omitempty"`
	Queue           string                           `json:"queue"`
	CustomerVisible *bool                            `json:"customerVisible,omitempty"`
	Search          string                           `json:"search,omitempty"`
	Custom          []savedViewCustomFilterCanonical `json:"custom"`
}

type savedViewCustomFilterCanonical struct {
	Definition savedViewDefinitionCanonical `json:"definition"`
	DataType   string                       `json:"dataType"`
	Operator   string                       `json:"operator"`
	Value      json.RawMessage              `json:"value"`
}

type savedViewDefinitionCanonical struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Version  uint64 `json:"version"`
	Digest   string `json:"digest"`
}

type savedViewSortCanonical struct {
	Source     string                        `json:"source"`
	CoreKey    string                        `json:"coreKey,omitempty"`
	Definition *savedViewDefinitionCanonical `json:"definition,omitempty"`
	Direction  string                        `json:"direction"`
	Nulls      string                        `json:"nulls"`
}

type savedViewColumnCanonical struct {
	Source     string                        `json:"source"`
	CoreKey    string                        `json:"coreKey,omitempty"`
	Definition *savedViewDefinitionCanonical `json:"definition,omitempty"`
	Width      uint16                        `json:"width"`
	Visible    bool                          `json:"visible"`
	Pin        string                        `json:"pin"`
}

// CanonicalSavedViewSpec is the only persistence encoding for a saved view.
// Its ordered structs and kernel-canonical sets make the digest reproducible;
// callers must never persist a separately handwritten representation.
func CanonicalSavedViewSpec(
	tenant kernel.EntityID,
	kind kernel.AggregateKind,
	spec kernel.SavedViewSpec,
) ([]byte, error) {
	if err := kernel.ValidateSavedViewSpec(tenant, kind, spec); err != nil {
		return nil, ErrInvalidInput
	}
	filters := spec.Filters()
	canonicalFilters := savedViewFiltersCanonical{
		States:     keyStringsForFingerprint(filters.States()),
		Severities: filters.Severities(), Priorities: filters.Priorities(),
		Queue: filters.Queue().String(), CustomerVisible: filters.CustomerVisible(),
		Search: filters.Search(), Custom: []savedViewCustomFilterCanonical{},
	}
	if value := filters.AssignedTeam(); value != nil {
		canonicalFilters.AssignedTeamID = value.String()
	}
	if value := filters.Assignee(); value != nil {
		canonicalFilters.AssigneeUserID = value.String()
	}
	if value := filters.ClaimedBy(); value != nil {
		canonicalFilters.ClaimedBy = value.String()
	}
	for _, filter := range filters.Custom() {
		canonicalFilters.Custom = append(canonicalFilters.Custom, savedViewCustomFilterCanonical{
			Definition: canonicalSavedViewDefinition(filter.Definition()),
			DataType:   string(filter.DataType()), Operator: "eq", Value: filter.CanonicalJSON(),
		})
	}
	canonicalSort := savedViewSortCanonical{
		Source: spec.Sort().Source().String(), Direction: spec.Sort().Direction().String(),
		Nulls: spec.Sort().Nulls().String(),
	}
	if key, core := spec.Sort().CoreKey(); core {
		canonicalSort.CoreKey = key.String()
	} else if definition, dynamic := spec.Sort().Definition(); dynamic {
		value := canonicalSavedViewDefinition(definition)
		canonicalSort.Definition = &value
	} else {
		return nil, ErrInvalidInput
	}
	columns := spec.Columns()
	canonicalColumns := make([]savedViewColumnCanonical, len(columns))
	for index, column := range columns {
		item := savedViewColumnCanonical{
			Source: column.Source().String(), Width: column.Width(),
			Visible: column.Visible(), Pin: column.Pin().String(),
		}
		if key, core := column.CoreKey(); core {
			item.CoreKey = key.String()
		} else if definition, dynamic := column.Definition(); dynamic {
			value := canonicalSavedViewDefinition(definition)
			item.Definition = &value
		} else {
			return nil, ErrInvalidInput
		}
		canonicalColumns[index] = item
	}
	encoded, err := json.Marshal(savedViewSpecCanonical{
		Version: 1, Filters: canonicalFilters, Sort: canonicalSort, Columns: canonicalColumns,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(encoded) > maximumSavedViewSpecBytes {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func SavedViewSpecDigest(
	tenant kernel.EntityID,
	kind kernel.AggregateKind,
	spec kernel.SavedViewSpec,
) ([sha256.Size]byte, error) {
	canonical, err := CanonicalSavedViewSpec(tenant, kind, spec)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func canonicalSavedViewDefinition(pin kernel.SavedViewDefinitionPin) savedViewDefinitionCanonical {
	digest := pin.Digest()
	return savedViewDefinitionCanonical{
		ID: pin.ID().String(), TenantID: pin.Tenant().String(), Kind: pin.Kind().String(),
		Key: pin.Key().String(), Version: pin.Version(), Digest: hex.EncodeToString(digest[:]),
	}
}

func bindSavedViewCommand(
	idempotencyKey string,
	action kernel.SavedViewAction,
	tenantID uuid.UUID,
	ownerMembershipID uuid.UUID,
	kind kernel.AggregateKind,
	viewID *uuid.UUID,
	expectedRevision uint64,
	name string,
	specDigest *[sha256.Size]byte,
) (SavedViewCommandBinding, error) {
	if !validIdempotencyKey(idempotencyKey) || !validWorkflowUUID(tenantID) ||
		!validWorkflowUUID(ownerMembershipID) ||
		kind != kernel.AggregateAlert && kind != kernel.AggregateCase ||
		!validSavedViewCommandShape(action, viewID, expectedRevision, name, specDigest) {
		return SavedViewCommandBinding{}, ErrInvalidInput
	}
	envelope := savedViewCommandEnvelope{
		Domain: savedViewCommandDomain, Action: action.String(), TenantID: tenantID.String(),
		OwnerMembershipID: ownerMembershipID.String(), Kind: kind.String(),
		ExpectedRevision: expectedRevision, Name: name,
	}
	if viewID != nil {
		envelope.ViewID = viewID.String()
	}
	if specDigest != nil {
		envelope.SpecDigest = hex.EncodeToString(specDigest[:])
	}
	fingerprint, err := savedViewCommandFingerprint(envelope)
	if err != nil {
		return SavedViewCommandBinding{}, ErrUnavailable
	}
	return SavedViewCommandBinding{
		Action:      action,
		KeyHash:     sha256.Sum256([]byte(savedViewIdempotencyDomain + idempotencyKey)),
		Fingerprint: fingerprint,
	}, nil
}

// BindSavedViewPlanCommand derives the immutable command identity for a closed
// domain plan. PostgreSQL adapters use it to verify that a write's separately
// carried plan and command binding still describe the same mutation.
func BindSavedViewPlanCommand(
	idempotencyKey string,
	ownerMembershipID uuid.UUID,
	plan kernel.SavedViewPlan,
) (SavedViewCommandBinding, error) {
	if !validIdempotencyKey(idempotencyKey) {
		return SavedViewCommandBinding{}, ErrInvalidInput
	}
	envelope, err := savedViewPlanCommandEnvelope(ownerMembershipID, plan)
	if err != nil {
		return SavedViewCommandBinding{}, err
	}
	fingerprint, err := savedViewCommandFingerprint(envelope)
	if err != nil {
		return SavedViewCommandBinding{}, ErrUnavailable
	}
	return SavedViewCommandBinding{
		Action:      plan.Action(),
		KeyHash:     sha256.Sum256([]byte(savedViewIdempotencyDomain + idempotencyKey)),
		Fingerprint: fingerprint,
	}, nil
}

// SavedViewCommandMatchesPlan compares the purpose-bound fingerprint without
// requiring the raw idempotency key. The key hash remains separately non-zero
// and database-lineage bound.
func SavedViewCommandMatchesPlan(
	binding SavedViewCommandBinding,
	ownerMembershipID uuid.UUID,
	plan kernel.SavedViewPlan,
) bool {
	if binding.Action != plan.Action() || binding.KeyHash == ([sha256.Size]byte{}) ||
		binding.Fingerprint == ([sha256.Size]byte{}) || !validWorkflowUUID(ownerMembershipID) {
		return false
	}
	envelope, err := savedViewPlanCommandEnvelope(ownerMembershipID, plan)
	if err != nil {
		return false
	}
	expected, err := savedViewCommandFingerprint(envelope)
	return err == nil && subtle.ConstantTimeCompare(expected[:], binding.Fingerprint[:]) == 1
}

func savedViewPlanCommandEnvelope(
	ownerMembershipID uuid.UUID,
	plan kernel.SavedViewPlan,
) (savedViewCommandEnvelope, error) {
	next := plan.Next()
	owner, err := entityID(ownerMembershipID)
	if err != nil || next.Owner() != owner {
		return savedViewCommandEnvelope{}, ErrInvalidInput
	}
	tenantID, viewID := uuidFromEntity(next.Tenant()), uuidFromEntity(next.ID())
	var boundViewID *uuid.UUID
	name := ""
	var digest *[sha256.Size]byte
	switch plan.Action() {
	case kernel.SavedViewCreate:
		name = next.Name()
	case kernel.SavedViewReplace:
		boundViewID, name = &viewID, next.Name()
	case kernel.SavedViewArchive, kernel.SavedViewRestore:
		boundViewID = &viewID
	default:
		return savedViewCommandEnvelope{}, ErrInvalidInput
	}
	if plan.Action() == kernel.SavedViewCreate || plan.Action() == kernel.SavedViewReplace {
		value, err := SavedViewSpecDigest(next.Tenant(), next.Kind(), next.Spec())
		if err != nil {
			return savedViewCommandEnvelope{}, err
		}
		digest = &value
	}
	if !validWorkflowUUID(tenantID) || !validWorkflowUUID(ownerMembershipID) ||
		(next.Kind() != kernel.AggregateAlert && next.Kind() != kernel.AggregateCase) ||
		!validSavedViewCommandShape(
			plan.Action(), boundViewID, plan.ExpectedRevision(), name, digest,
		) {
		return savedViewCommandEnvelope{}, ErrInvalidInput
	}
	envelope := savedViewCommandEnvelope{
		Domain: savedViewCommandDomain, Action: plan.Action().String(), TenantID: tenantID.String(),
		OwnerMembershipID: ownerMembershipID.String(), Kind: next.Kind().String(),
		ExpectedRevision: plan.ExpectedRevision(), Name: name,
	}
	if boundViewID != nil {
		envelope.ViewID = boundViewID.String()
	}
	if digest != nil {
		envelope.SpecDigest = hex.EncodeToString(digest[:])
	}
	return envelope, nil
}

func savedViewCommandFingerprint(envelope savedViewCommandEnvelope) ([sha256.Size]byte, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func validSavedViewCommandShape(
	action kernel.SavedViewAction,
	viewID *uuid.UUID,
	expectedRevision uint64,
	name string,
	specDigest *[sha256.Size]byte,
) bool {
	hasDigest := specDigest != nil && *specDigest != ([sha256.Size]byte{})
	switch action {
	case kernel.SavedViewCreate:
		return viewID == nil && expectedRevision == 0 && validText(name, 120, false) && hasDigest
	case kernel.SavedViewReplace:
		return viewID != nil && validWorkflowUUID(*viewID) && expectedRevision > 0 &&
			expectedRevision < maxResourceVersion && validText(name, 120, false) && hasDigest
	case kernel.SavedViewArchive, kernel.SavedViewRestore:
		return viewID != nil && validWorkflowUUID(*viewID) && expectedRevision > 0 &&
			expectedRevision < maxResourceVersion && name == "" && specDigest == nil
	default:
		return false
	}
}
