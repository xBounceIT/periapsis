package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type ticketSavedViewExecution struct {
	record        application.SavedViewRecord
	filters       []ticketCustomFieldFilterPin
	sort          kernel.SavedViewSort
	columns       []kernel.SavedViewColumn
	canonicalHash [sha256.Size]byte
}

// resolveTicketSavedViewExecution loads the private view and re-resolves every
// dynamic definition inside the same REPEATABLE READ snapshot as the ticket
// query. The persisted specification is accepted only when the live resolver
// reproduces its exact canonical bytes and digest.
func resolveTicketSavedViewExecution(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.ListInput,
	access application.LiveAccess,
) (*ticketSavedViewExecution, application.ListInput, error) {
	if input.SavedViewID == nil {
		return nil, input, nil
	}
	if access.Authority.Principal() != kernel.PrincipalOperator ||
		!authorizationUUIDv7(*input.SavedViewID) {
		return nil, application.ListInput{}, application.ErrForbidden
	}
	membershipID := uuid.UUID(access.MembershipID.Bytes())
	actorID := uuid.UUID(access.Authority.Actor().Bytes())
	if !authorizationUUIDv7(membershipID) || !authorizationUUIDv7(actorID) {
		return nil, application.ListInput{}, application.ErrForbidden
	}
	getRequest := savedViewGetRequestV1{
		SchemaVersion: 1, TenantID: tenantID.String(), ActorID: actorID.String(),
		OwnerMembershipID: membershipID.String(), AggregateKind: kind.String(),
		ViewID: input.SavedViewID.String(),
	}
	getPayload, err := marshalSavedViewWire(getRequest, maximumSavedViewGetRequestBytes)
	if err != nil {
		return nil, application.ListInput{}, err
	}
	var getResponse []byte
	if err := tx.QueryRow(ctx, savedViewGetABIQuery, getPayload).Scan(&getResponse); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, application.ListInput{}, application.ErrNotFound
		}
		return nil, application.ListInput{}, mapSavedViewDatabaseError(err)
	}
	record, err := restoreSavedViewGetResponse(getResponse, tenantID, membershipID, kind)
	if err != nil || savedViewUUID(record.View.ID()) != *input.SavedViewID {
		return nil, application.ListInput{}, application.ErrUnavailable
	}
	if record.View.Status() != kernel.SavedViewActive {
		return nil, application.ListInput{}, application.ErrConflict
	}
	resolutionInput, err := application.SavedViewSpecInputFromResolved(record.View.Spec())
	if err != nil {
		return nil, application.ListInput{}, application.ErrUnavailable
	}
	resolveRequest, err := newSavedViewResolveSpecRequestFromValidated(
		tenantID, actorID, membershipID, kind, resolutionInput,
	)
	if err != nil {
		return nil, application.ListInput{}, err
	}
	resolvePayload, err := marshalSavedViewWire(resolveRequest, maximumSavedViewResolveRequestBytes)
	if err != nil {
		return nil, application.ListInput{}, err
	}
	var resolveResponse []byte
	if err := tx.QueryRow(ctx, savedViewResolveSpecABIQuery, resolvePayload).Scan(&resolveResponse); err != nil {
		return nil, application.ListInput{}, mapSavedViewRequiredRowError(err)
	}
	resolved, err := restoreSavedViewResolvedSpec(resolveResponse, tenantID, kind, resolutionInput)
	if err != nil {
		return nil, application.ListInput{}, err
	}
	persistedCanonical, err := application.CanonicalSavedViewSpec(record.View.Tenant(), kind, record.View.Spec())
	if err != nil {
		return nil, application.ListInput{}, application.ErrUnavailable
	}
	resolvedCanonical, err := application.CanonicalSavedViewSpec(record.View.Tenant(), kind, resolved)
	if err != nil || !bytes.Equal(persistedCanonical, resolvedCanonical) ||
		sha256.Sum256(resolvedCanonical) != record.SpecDigest {
		return nil, application.ListInput{}, application.ErrConflict
	}
	execution := &ticketSavedViewExecution{
		record: record, sort: resolved.Sort(), columns: resolved.Columns(),
		canonicalHash: sha256.Sum256(resolvedCanonical),
	}
	effective, err := savedViewEffectiveListInput(input, resolved, execution)
	if err != nil {
		return nil, application.ListInput{}, err
	}
	return execution, effective, nil
}

func savedViewEffectiveListInput(
	request application.ListInput,
	spec kernel.SavedViewSpec,
	execution *ticketSavedViewExecution,
) (application.ListInput, error) {
	filters := spec.Filters()
	effective := application.ListInput{
		After: request.After, Limit: request.Limit, SavedViewID: request.SavedViewID,
		States: filters.States(), Severities: filters.Severities(), Priorities: filters.Priorities(),
		Queue: filters.Queue().String(), CustomerVisible: filters.CustomerVisible(), Search: filters.Search(),
	}
	if effective.Queue == "all" {
		effective.Queue = ""
	}
	if value := filters.AssignedTeam(); value != nil {
		identifier := uuid.UUID(value.Bytes())
		effective.AssignedTeamID = &identifier
	}
	if value := filters.Assignee(); value != nil {
		identifier := uuid.UUID(value.Bytes())
		effective.AssigneeUserID = &identifier
	}
	if value := filters.ClaimedBy(); value != nil {
		identifier := uuid.UUID(value.Bytes())
		effective.ClaimedBy = &identifier
	}
	for _, filter := range filters.Custom() {
		pin := filter.Definition()
		execution.filters = append(execution.filters, ticketCustomFieldFilterPin{
			DefinitionID: uuid.UUID(pin.ID().Bytes()), DefinitionDigest: pin.Digest(),
			Key: pin.Key().String(), SchemaVersion: pin.Version(), DataType: filter.DataType(),
			Canonical: json.RawMessage(filter.CanonicalJSON()),
		})
	}
	if sortKey, core := spec.Sort().CoreKey(); core {
		effective.Sort = savedViewCoreSortName(sortKey.String(), spec.Sort().Direction().String())
		if effective.Sort == "" {
			return application.ListInput{}, application.ErrUnavailable
		}
	}
	return effective, nil
}

func savedViewCoreSortName(key, direction string) string {
	switch key + ":" + direction {
	case "updated_at:desc":
		return "updated_at_desc"
	case "updated_at:asc":
		return "updated_at_asc"
	case "created_at:desc":
		return "created_at_desc"
	case "created_at:asc":
		return "created_at_asc"
	case "priority:desc":
		return "priority_desc"
	case "oldest_unclaimed:asc":
		return "oldest_unclaimed"
	default:
		return ""
	}
}

func dynamicCustomFilterPins(filters []ticketCustomFieldFilterPin) []ticketCustomFieldFilterPin {
	result := make([]ticketCustomFieldFilterPin, len(filters))
	copy(result, filters)
	for index := range result {
		result[index].Canonical = append(json.RawMessage(nil), filters[index].Canonical...)
	}
	return result
}
