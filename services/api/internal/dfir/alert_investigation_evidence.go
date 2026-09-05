package dfir

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func (service *AlertInvestigationService) CollectEvidence(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertEvidenceCollectCommand,
) (MutationResult[kernel.AlertEvidence], error) {
	command.RetentionUntil = cloneTime(command.RetentionUntil)
	access, membershipID, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityEvidenceManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	tenant, _, conversionErr := actorEntities(actor)
	if conversionErr != nil {
		return MutationResult[kernel.AlertEvidence]{}, ErrForbidden
	}
	userID, conversionErr := kernel.NewEntityID([16]byte(actor.UserID))
	if conversionErr != nil {
		return MutationResult[kernel.AlertEvidence]{}, ErrForbidden
	}
	intent := kernel.AlertEvidenceInput{
		ID: command.EvidenceID, TenantID: tenant, AlertID: command.AlertID,
		StorageObjectID: command.StorageObjectID, InitialCustodyEventID: command.InitialCustodyEventID,
		Title: command.Title, Description: command.Description, EvidenceType: command.EvidenceType,
		Classification: command.Classification, CollectedAt: command.CollectedAt,
		CollectedBy: membershipID, InitialCustodyActorID: userID,
		Source: command.Source, RetentionUntil: command.RetentionUntil,
		LegalHold: command.LegalHold,
	}
	if err := kernel.ValidateAlertEvidenceCollectionIntent(intent); err != nil {
		return MutationResult[kernel.AlertEvidence]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	if command.CollectedAt.After(now) {
		return MutationResult[kernel.AlertEvidence]{}, ErrInvalidInput
	}
	contract, err := newAlertMutationContract(
		actor, command.AlertID, command.Envelope, access, CapabilityEvidenceManage,
		operationAlertEvidenceCreate, "Alert evidence collected",
		alertEvidenceCollectRequestFingerprint(command, membershipID, userID),
	)
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	var built alertCallbackCapture[kernel.AlertEvidence]
	result, err := service.repository.CommitAlertEvidence(ctx, AlertEvidenceCreateWrite{
		Contract: contract, EvidenceID: command.EvidenceID, StorageObjectID: command.StorageObjectID,
		Build: func(storage kernel.StorageObject) (kernel.AlertEvidence, error) {
			built.begin()
			if err := ctx.Err(); err != nil {
				return kernel.AlertEvidence{}, err
			}
			if !service.validEvidenceStorage(storage, tenantID, command.StorageObjectID) ||
				storage.ContentSHA256() == "" {
				return kernel.AlertEvidence{}, ErrUnavailable
			}
			input := intent
			input.ContentSHA256, input.SizeBytes = storage.ContentSHA256(), storage.SizeBytes()
			input.DetectedMIME, input.ScanState = storage.DetectedMIME(), storage.State()
			evidence, buildErr := kernel.NewAlertEvidence(input)
			if buildErr != nil || evidence.Classification() != storage.Classification() {
				return kernel.AlertEvidence{}, ErrInvalidInput
			}
			built.complete(evidence)
			return evidence, nil
		},
	})
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, alertInvestigationMutationError(err)
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	if !validAlertEvidenceCreateResult(result.Resource, tenant, command, membershipID, userID) {
		return MutationResult[kernel.AlertEvidence]{}, ErrUnavailable
	}
	builtEvidence, buildCalls := built.snapshot()
	if result.Replayed && buildCalls != 0 || !result.Replayed &&
		(buildCalls != 1 || !sameFingerprint(
			alertEvidenceFingerprint(result.Resource, 0), alertEvidenceFingerprint(builtEvidence, 0),
		)) {
		return MutationResult[kernel.AlertEvidence]{}, ErrUnavailable
	}
	return result, nil
}

func validAlertEvidenceCreateResult(
	evidence kernel.AlertEvidence,
	tenant kernel.EntityID,
	command AlertEvidenceCollectCommand,
	membershipID kernel.EntityID,
	userID kernel.EntityID,
) bool {
	if !validAlertEvidenceProjection(evidence, tenant, command.AlertID, command.EvidenceID) ||
		evidence.Version() != 1 || evidence.StorageObjectID() != command.StorageObjectID ||
		evidence.Title() != command.Title || evidence.Description() != command.Description ||
		evidence.EvidenceType() != command.EvidenceType || evidence.Classification() != command.Classification ||
		!evidence.CollectedAt().Equal(command.CollectedAt) || evidence.CollectedBy() != membershipID ||
		evidence.Source() != command.Source || evidence.LegalHold() != command.LegalHold {
		return false
	}
	events := evidence.CustodyEvents()
	if len(events) == 0 || events[0].ID() != command.InitialCustodyEventID ||
		events[0].ActorID() != userID {
		return false
	}
	left, right := evidence.RetentionUntil(), command.RetentionUntil
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func (service *AlertInvestigationService) AppendCustody(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertCustodyCommand,
) (MutationResult[kernel.AlertEvidence], error) {
	command.LegalHold = cloneBool(command.LegalHold)
	command.RetentionUntil = cloneTime(command.RetentionUntil)
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityEvidenceManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	actorID, conversionErr := kernel.NewEntityID([16]byte(actor.UserID))
	if conversionErr != nil {
		return MutationResult[kernel.AlertEvidence]{}, ErrForbidden
	}
	if !validAlertMutationVersion(command.ExpectedVersion) || command.EvidenceID == (kernel.EntityID{}) ||
		command.EventID == (kernel.EntityID{}) || command.ExpectedVersion >= kernel.MaximumCustodyEvents ||
		!validAlertCustodyShape(command) || !validAlertSingleLineText(command.Reason, 2_000, false) ||
		!validOptionalAlertInstant(command.RetentionUntil) {
		return MutationResult[kernel.AlertEvidence]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	event := kernel.CustodyEventInput{
		ID: command.EventID, ActorID: actorID, Action: command.Action,
		Reason: command.Reason, OccurredAt: now,
	}
	contract, err := newAlertMutationContract(
		actor, command.AlertID, command.Envelope, access, CapabilityEvidenceManage,
		operationAlertEvidenceCustody, command.Reason, alertCustodyRequestFingerprint(command, actorID),
	)
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	var applied alertCallbackCapture[kernel.AlertEvidence]
	result, err := service.repository.MutateAlertEvidence(ctx, AlertEvidenceMutationWrite{
		Contract: contract, EvidenceID: command.EvidenceID, ExpectedVersion: command.ExpectedVersion,
		Apply: func(current kernel.AlertEvidence) (kernel.AlertEvidence, error) {
			applied.begin()
			if err := ctx.Err(); err != nil {
				return kernel.AlertEvidence{}, err
			}
			events := current.CustodyEvents()
			if !validAlertEvidenceProjection(current, current.TenantID(), command.AlertID, command.EvidenceID) ||
				current.TenantID().String() != tenantID.String() || len(events) == 0 {
				return kernel.AlertEvidence{}, ErrUnavailable
			}
			if now.Before(events[len(events)-1].OccurredAt()) {
				return kernel.AlertEvidence{}, ErrUnavailable
			}
			updated, applyErr := applyAlertCustody(current, command, event)
			if applyErr == nil {
				applied.complete(updated)
			}
			return updated, applyErr
		},
	})
	if err != nil {
		return MutationResult[kernel.AlertEvidence]{}, alertInvestigationMutationError(err)
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	tenant, _, conversionErr := actorEntities(actor)
	if conversionErr != nil || !validAlertEvidenceMutationResult(result.Resource, tenant, command, actorID) {
		return MutationResult[kernel.AlertEvidence]{}, ErrUnavailable
	}
	appliedEvidence, applyCalls := applied.snapshot()
	if result.Replayed && applyCalls != 0 || !result.Replayed &&
		(applyCalls != 1 || !sameFingerprint(
			alertEvidenceFingerprint(result.Resource, 0), alertEvidenceFingerprint(appliedEvidence, 0),
		)) {
		return MutationResult[kernel.AlertEvidence]{}, ErrUnavailable
	}
	return result, nil
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (service *AlertInvestigationService) validEvidenceStorage(
	storage kernel.StorageObject,
	tenantID uuid.UUID,
	storageID kernel.EntityID,
) bool {
	return storage.TenantID().String() == tenantID.String() && storage.ID() == storageID &&
		storage.Bucket() == service.bucket && storage.ObjectKey() == tenantID.String()+"/"+storageID.String()
}

func validAlertEvidenceProjection(
	evidence kernel.AlertEvidence,
	tenant kernel.EntityID,
	alertID kernel.EntityID,
	evidenceID kernel.EntityID,
) bool {
	return evidence.TenantID() == tenant && evidence.AlertID() == alertID && evidence.ID() == evidenceID &&
		evidence.Version() > 0 && uint64(len(evidence.CustodyEvents())) <= kernel.MaximumCustodyEvents &&
		evidence.VerifyCustodyChain()
}

func validAlertCustodyShape(command AlertCustodyCommand) bool {
	switch command.Action {
	case kernel.CustodyAccessed, kernel.CustodyTransferred, kernel.CustodySealed, kernel.CustodyUnsealed,
		kernel.CustodyDestroyed:
		return command.NextScanState == "" && command.LegalHold == nil && !command.RetentionSet &&
			command.RetentionUntil == nil
	case kernel.CustodyScanStateChanged:
		return validAlertScanState(command.NextScanState) && command.LegalHold == nil && !command.RetentionSet &&
			command.RetentionUntil == nil
	case kernel.CustodyLegalHoldPlaced:
		return command.NextScanState == "" && command.LegalHold != nil && *command.LegalHold &&
			!command.RetentionSet && command.RetentionUntil == nil
	case kernel.CustodyLegalHoldReleased:
		return command.NextScanState == "" && command.LegalHold != nil && !*command.LegalHold &&
			!command.RetentionSet && command.RetentionUntil == nil
	case kernel.CustodyRetentionChanged:
		return command.NextScanState == "" && command.LegalHold == nil && command.RetentionSet
	default:
		return false
	}
}

func validAlertScanState(value kernel.ScanState) bool {
	switch value {
	case kernel.ScanPendingUpload, kernel.ScanUploaded, kernel.ScanVerifying, kernel.ScanQuarantined,
		kernel.ScanScanning, kernel.ScanAvailable, kernel.ScanRejected, kernel.ScanFailed,
		kernel.ScanRetained, kernel.ScanDeleted:
		return true
	default:
		return false
	}
}

func applyAlertCustody(
	current kernel.AlertEvidence,
	command AlertCustodyCommand,
	event kernel.CustodyEventInput,
) (kernel.AlertEvidence, error) {
	switch command.Action {
	case kernel.CustodyAccessed, kernel.CustodyTransferred, kernel.CustodySealed, kernel.CustodyUnsealed:
		return current.AppendCustodyEvent(command.ExpectedVersion, event)
	case kernel.CustodyScanStateChanged:
		return current.ChangeScanState(command.ExpectedVersion, event, command.NextScanState)
	case kernel.CustodyLegalHoldPlaced, kernel.CustodyLegalHoldReleased:
		return current.ChangeLegalHold(command.ExpectedVersion, event, *command.LegalHold)
	case kernel.CustodyRetentionChanged:
		return current.ChangeRetention(command.ExpectedVersion, event, command.RetentionUntil)
	case kernel.CustodyDestroyed:
		return current.Destroy(command.ExpectedVersion, event)
	default:
		return kernel.AlertEvidence{}, kernel.ErrInvalidEvidence
	}
}

func validAlertEvidenceMutationResult(
	evidence kernel.AlertEvidence,
	tenant kernel.EntityID,
	command AlertCustodyCommand,
	actorID kernel.EntityID,
) bool {
	if !validAlertEvidenceProjection(evidence, tenant, command.AlertID, command.EvidenceID) ||
		evidence.Version() != command.ExpectedVersion+1 {
		return false
	}
	events := evidence.CustodyEvents()
	if len(events) == 0 {
		return false
	}
	last := events[len(events)-1]
	if last.ID() != command.EventID || last.Action() != command.Action || last.ActorID() != actorID ||
		last.Reason() != command.Reason {
		return false
	}
	switch command.Action {
	case kernel.CustodyScanStateChanged:
		return evidence.ScanState() == command.NextScanState
	case kernel.CustodyLegalHoldPlaced, kernel.CustodyLegalHoldReleased:
		return command.LegalHold != nil && evidence.LegalHold() == *command.LegalHold
	case kernel.CustodyRetentionChanged:
		left, right := evidence.RetentionUntil(), command.RetentionUntil
		return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
	case kernel.CustodyDestroyed:
		return evidence.Destroyed() && evidence.ScanState() == kernel.ScanDeleted
	default:
		return true
	}
}
