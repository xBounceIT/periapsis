package httpserver

import (
	"encoding/hex"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func mapTicketBulkMutationResult(result application.TicketBulkResult) (contract.TicketBulkJobMutationResult, error) {
	job, err := mapTicketBulkJob(result.Record)
	if err != nil {
		return contract.TicketBulkJobMutationResult{}, err
	}
	return contract.TicketBulkJobMutationResult{Job: job, Replayed: result.Replayed}, nil
}

func mapTicketBulkJob(record application.TicketBulkRecord) (contract.TicketBulkJob, error) {
	job := record.Job
	if err := kernel.ValidateTicketBulkJob(job); err != nil {
		return contract.TicketBulkJob{}, application.ErrUnavailable
	}
	definition := job.Definition()
	kind := contract.TicketResourceKind(definition.Kind().String())
	state := contract.TicketBulkState(job.State().String())
	if !kind.Valid() || !state.Valid() || job.Revision() > 2_147_483_647 {
		return contract.TicketBulkJob{}, application.ErrUnavailable
	}
	selection, err := mapTicketBulkSelection(definition.Selection(), record.Query)
	if err != nil {
		return contract.TicketBulkJob{}, err
	}
	mutation, err := mapTicketBulkMutation(definition.Mutation())
	if err != nil {
		return contract.TicketBulkJob{}, err
	}
	progress := job.Progress().Snapshot()
	result := contract.TicketBulkJob{
		ActiveBatch: job.ActiveBatch(), AvailableAt: job.AvailableAt(), ExpiresAt: job.ExpiresAt(),
		Id: uuid.UUID(definition.ID().Bytes()), Kind: kind, Mutation: mutation,
		OwnerMembershipId: uuid.UUID(definition.OwnerMembership().Bytes()),
		Progress: contract.TicketBulkProgress{
			AuthorizationDenied: int32(progress.AuthorizationDenied), AuthorizationRevoked: int32(progress.AuthorizationRevoked),
			Cancelled: int32(progress.Cancelled), InternalFailure: int32(progress.InternalFailure),
			NoChange: int32(progress.NoChange), NotFoundOrHidden: int32(progress.NotFoundOrHidden),
			Rejected: int32(progress.Rejected), Succeeded: int32(progress.Succeeded),
			Total: int32(progress.Total), VersionConflict: int32(progress.VersionConflict),
		},
		RequestedAt: job.RequestedAt(), RequesterUserId: uuid.UUID(definition.Requester().Bytes()),
		Revision: int64(job.Revision()), Selection: selection, State: state,
		TenantId: uuid.UUID(definition.Tenant().Bytes()), UpdatedAt: job.UpdatedAt(),
	}
	if terminal := job.TerminalAt(); terminal != nil {
		value := *terminal
		result.TerminalAt = &value
	}
	return result, nil
}

func mapTicketBulkSelection(
	selection kernel.TicketBulkSelection,
	query *application.TicketBulkQuerySnapshot,
) (contract.TicketBulkSelection, error) {
	if selection.TargetCount() == 0 || selection.TargetCount() > kernel.TicketBulkMaximumTargets {
		return contract.TicketBulkSelection{}, application.ErrUnavailable
	}
	result := contract.TicketBulkSelection{
		Source:          contract.TicketBulkSelectionSource(selection.Source().String()),
		TargetCount:     int32(selection.TargetCount()),
		TargetSetSha256: ticketBulkDigestString(selection.TargetSetDigest()),
	}
	if !result.Source.Valid() || result.TargetSetSha256 == ticketBulkZeroDigest {
		return contract.TicketBulkSelection{}, application.ErrUnavailable
	}
	switch selection.Source() {
	case kernel.TicketBulkSelectionExplicit:
		if query != nil || selection.QueryDigest() != ([32]byte{}) || selection.SavedView() != nil {
			return contract.TicketBulkSelection{}, application.ErrUnavailable
		}
		targets := selection.ExplicitTargets()
		if len(targets) != int(selection.TargetCount()) {
			return contract.TicketBulkSelection{}, application.ErrUnavailable
		}
		mapped := make([]contract.TicketBulkTargetPin, len(targets))
		for index, target := range targets {
			if target.Version() == 0 || target.Version() > 2_147_483_647 {
				return contract.TicketBulkSelection{}, application.ErrUnavailable
			}
			mapped[index] = contract.TicketBulkTargetPin{
				Id: uuid.UUID(target.ID().Bytes()), ExpectedVersion: int64(target.Version()),
			}
		}
		result.Targets = &mapped
	case kernel.TicketBulkSelectionQuery:
		if query == nil || query.QueryDigest() != selection.QueryDigest() ||
			query.CatalogDigest() == ([32]byte{}) || query.Kind() == 0 {
			return contract.TicketBulkSelection{}, application.ErrUnavailable
		}
		effectiveSpec, err := mapSavedTicketViewSpec(query.Spec())
		if err != nil {
			return contract.TicketBulkSelection{}, application.ErrUnavailable
		}
		queryDigest := ticketBulkDigestString(query.QueryDigest())
		catalogDigest := ticketBulkDigestString(query.CatalogDigest())
		querySource := contract.TicketBulkSelectionQuerySource(query.Source().String())
		if queryDigest == ticketBulkZeroDigest || catalogDigest == ticketBulkZeroDigest || !querySource.Valid() {
			return contract.TicketBulkSelection{}, application.ErrUnavailable
		}
		result.QuerySha256, result.CatalogSha256 = &queryDigest, &catalogDigest
		result.QuerySource, result.EffectiveSpec = &querySource, &effectiveSpec
		selectionPin, queryPin := selection.SavedView(), query.SavedView()
		if (selectionPin == nil) != (queryPin == nil) {
			return contract.TicketBulkSelection{}, application.ErrUnavailable
		}
		if selectionPin != nil {
			if selectionPin.ID() != queryPin.ID() || selectionPin.Owner() != queryPin.Owner() ||
				selectionPin.Revision() != queryPin.Revision() || selectionPin.SpecDigest() != queryPin.SpecDigest() ||
				selectionPin.Revision() > 2_147_483_647 {
				return contract.TicketBulkSelection{}, application.ErrUnavailable
			}
			result.SavedView = &contract.TicketBulkSavedViewPin{
				Id: uuid.UUID(selectionPin.ID().Bytes()), OwnerMembershipId: uuid.UUID(selectionPin.Owner().Bytes()),
				Revision: int64(selectionPin.Revision()), SpecSha256: ticketBulkDigestString(selectionPin.SpecDigest()),
			}
		}
	default:
		return contract.TicketBulkSelection{}, application.ErrUnavailable
	}
	return result, nil
}

func mapTicketBulkMutation(mutation kernel.TicketBulkMutation) (contract.TicketBulkMutationRequest, error) {
	result := contract.TicketBulkMutationRequest{
		Action: contract.TicketBulkMutationRequestAction(mutation.Action().String()),
	}
	if !result.Action.Valid() {
		return contract.TicketBulkMutationRequest{}, application.ErrUnavailable
	}
	switch mutation.Action() {
	case kernel.ActionTransition:
		transition, to, ok := mutation.Transition()
		if !ok {
			return contract.TicketBulkMutationRequest{}, application.ErrUnavailable
		}
		transitionValue, toValue := contract.WorkflowTransitionKey(transition.String()), contract.WorkflowStateKey(to.String())
		result.Transition, result.To = &transitionValue, &toValue
	case kernel.ActionAssign, kernel.ActionTransfer:
		team, assignee, ok := mutation.Assignment()
		if !ok {
			return contract.TicketBulkMutationRequest{}, application.ErrUnavailable
		}
		teamID := uuid.UUID(team.Bytes())
		result.TeamId = &teamID
		if assignee != nil {
			assigneeID := uuid.UUID(assignee.Bytes())
			result.AssigneeId = &assigneeID
		}
	case kernel.ActionClaim:
		team, ok := mutation.ClaimTeam()
		if !ok {
			return contract.TicketBulkMutationRequest{}, application.ErrUnavailable
		}
		teamID := uuid.UUID(team.Bytes())
		result.TeamId = &teamID
	case kernel.ActionRelease:
	default:
		return contract.TicketBulkMutationRequest{}, application.ErrUnavailable
	}
	return result, nil
}

func mapTicketBulkResultPage(page application.TicketBulkResultPage) (contract.TicketBulkTargetResultPage, error) {
	items := make([]contract.TicketBulkTargetResult, len(page.Items))
	for index, item := range page.Items {
		code := contract.TicketBulkTargetResultCode(item.Result.String())
		if item.Sequence == 0 || item.Sequence > kernel.TicketBulkMaximumTargets ||
			item.TargetVersion == 0 || item.TargetVersion > 2_147_483_647 || !code.Valid() || item.RecordedAt.IsZero() {
			return contract.TicketBulkTargetResultPage{}, application.ErrUnavailable
		}
		items[index] = contract.TicketBulkTargetResult{
			RecordedAt: item.RecordedAt, Result: code, Sequence: int32(item.Sequence),
			TargetId: uuid.UUID(item.TargetID), TargetVersion: int64(item.TargetVersion),
		}
	}
	result := contract.TicketBulkTargetResultPage{Items: items}
	if page.Next != "" {
		value := page.Next
		result.NextCursor = &value
	}
	return result, nil
}

const ticketBulkZeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

func ticketBulkDigestString(value [32]byte) string {
	return hex.EncodeToString(value[:])
}
