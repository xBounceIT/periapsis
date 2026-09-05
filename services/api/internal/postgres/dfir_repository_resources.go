package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (repository *DFIRRepository) CreateIndicator(
	ctx context.Context,
	write application.IndicatorWrite,
) (application.MutationResult[kernel.Indicator], error) {
	if !validDFIRCommand(write.Command, "dfir.ioc.create") || write.ExpectedVersion != 0 {
		return application.MutationResult[kernel.Indicator]{}, application.ErrRepositoryConflict
	}
	return repository.writeIndicator(ctx, write, false)
}

func (repository *DFIRRepository) ReplaceIndicator(
	ctx context.Context,
	write application.IndicatorWrite,
) (application.MutationResult[kernel.Indicator], error) {
	if !validDFIRCommand(write.Command, "dfir.ioc.replace") || write.ExpectedVersion == 0 ||
		write.ExpectedVersion >= kernel.MaximumResourceVersion {
		return application.MutationResult[kernel.Indicator]{}, application.ErrRepositoryPrecondition
	}
	return repository.writeIndicator(ctx, write, true)
}

func (repository *DFIRRepository) writeIndicator(
	ctx context.Context,
	write application.IndicatorWrite,
	replace bool,
) (application.MutationResult[kernel.Indicator], error) {
	if write.AlertID != (kernel.EntityID{}) {
		if write.CaseID != (kernel.EntityID{}) {
			return application.MutationResult[kernel.Indicator]{}, application.ErrRepositoryConflict
		}
		return repository.writeAlertIndicator(ctx, write, replace)
	}
	if write.CaseID == (kernel.EntityID{}) {
		return application.MutationResult[kernel.Indicator]{}, application.ErrRepositoryForbidden
	}
	tenantID := uuid.UUID(write.Indicator.TenantID().Bytes())
	caseID := uuid.UUID(write.CaseID.Bytes())
	id := uuid.UUID(write.Indicator.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Indicator], error) {
			if _, accessErr := authorizeDFIRWrite(ctx, tx, write.Actor, tenantID, application.CapabilityIOCManage, caseID); accessErr != nil {
				return application.MutationResult[kernel.Indicator]{}, accessErr
			}
			root := dfirSharedRoot{kind: kernel.EntityCase, id: caseID}
			if replace {
				if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityIOC, id, root); accessErr != nil {
					return application.MutationResult[kernel.Indicator]{}, accessErr
				}
			}
			idsNeeded := 4
			if !replace {
				idsNeeded++
			}
			ids, idErr := phase4NewIDs(repository.newID, idsNeeded)
			if idErr != nil {
				return application.MutationResult[kernel.Indicator]{}, idErr
			}
			resultVersion := uint64(1)
			if replace {
				resultVersion = write.ExpectedVersion + 1
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindIOC, resourceID: id, resultVersion: resultVersion,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Indicator]{}, reserveErr
			}
			if reservation.replayed {
				if !replace {
					if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityIOC, id, root); accessErr != nil {
						return application.MutationResult[kernel.Indicator]{}, accessErr
					}
				}
				historical, decodeErr := decodeDFIRIndicatorResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Indicator]{}, decodeErr
				}
				return application.MutationResult[kernel.Indicator]{Resource: historical, Replayed: true}, nil
			}
			current, currentVersion, loadErr := loadDFIRIndicator(ctx, tx, tenantID, id)
			if loadErr == nil {
				linked, linkErr := dfirResourceLinkedToCase(ctx, tx, "public.dfir_ioc_links", "ioc_id", tenantID, caseID, id)
				if linkErr != nil {
					return application.MutationResult[kernel.Indicator]{}, linkErr
				}
				if !linked {
					return application.MutationResult[kernel.Indicator]{}, authorization.ErrForbidden
				}
				if !replace || currentVersion != write.ExpectedVersion {
					return application.MutationResult[kernel.Indicator]{}, application.ErrRepositoryPrecondition
				}
			} else if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.MutationResult[kernel.Indicator]{}, loadErr
			} else if replace {
				return application.MutationResult[kernel.Indicator]{}, pgx.ErrNoRows
			}
			if replace {
				if updateErr := updateDFIRIndicator(ctx, tx, write); updateErr != nil {
					return application.MutationResult[kernel.Indicator]{}, updateErr
				}
			} else {
				if insertErr := insertDFIRIndicator(ctx, tx, write); insertErr != nil {
					return application.MutationResult[kernel.Indicator]{}, insertErr
				}
				if _, linkErr := tx.Exec(ctx, `INSERT INTO public.dfir_ioc_links
					(id, tenant_id, ioc_id, case_id, created_by_membership_id)
					VALUES ($1, $2, $3, $4, $5)`, ids[4], tenantID, id, caseID, write.Actor.MembershipID); linkErr != nil {
					return application.MutationResult[kernel.Indicator]{}, linkErr
				}
			}
			version := int64(1)
			action := "dfir.ioc.created"
			before := map[string]any{}
			if replace {
				version = int64(write.ExpectedVersion + 1)
				action = "dfir.ioc.replaced"
				before = dfirIndicatorJournal(current, currentVersion)
			}
			kind := string(kernel.EntityIOC)
			if effectErr := appendDFIRMutationEffects(ctx, tx, write.BaseWrite, ids[1:4], phase4MutationEffects{
				PermissionKey: "dfir.ioc.manage", Action: action,
				ResourceType: "dfir_ioc", ResourceID: id, ResourceVersion: version,
				CaseID: &caseID, ActivityResourceKind: &kind, ActivityResourceID: &id,
				Summary: "DFIR indicator changed", Before: before,
				After:    dfirIndicatorJournal(write.Indicator, uint64(version)),
				Metadata: map[string]any{"commandOperation": write.Command.Operation},
			}); effectErr != nil {
				return application.MutationResult[kernel.Indicator]{}, effectErr
			}
			stored, storedVersion, storedErr := loadDFIRIndicator(ctx, tx, tenantID, id)
			if storedErr != nil || storedVersion != uint64(version) || !sameDFIRIndicator(stored, write.Indicator) {
				if storedErr != nil {
					return application.MutationResult[kernel.Indicator]{}, storedErr
				}
				return application.MutationResult[kernel.Indicator]{}, unexpectedDFIRProjection("divergent IOC after mutation")
			}
			if activityErr := repository.appendSharedResourceActivities(ctx, tx, reservation.commandID, write.BaseWrite, kernel.EntityIOC, id); activityErr != nil {
				return application.MutationResult[kernel.Indicator]{}, activityErr
			}
			document, snapshotErr := encodeDFIRIndicatorResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Indicator]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Indicator]{}, storeErr
			}
			return application.MutationResult[kernel.Indicator]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func insertDFIRIndicator(ctx context.Context, tx databaseTransaction, write application.IndicatorWrite) error {
	value := write.Indicator
	var ipValue any
	if value.Type() == kernel.IndicatorIPv4 || value.Type() == kernel.IndicatorIPv6 {
		ipValue = value.NormalizedValue()
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO public.dfir_iocs (
			id, tenant_id, type, value, normalized_value, ip_value,
			description, source, confidence, tlp, first_seen, last_seen,
			malicious_state, tags, enrichment, created_by_membership_id,
			updated_by_membership_id, version
		) VALUES (
			$1, $2, $3::public.dfir_indicator_type, $4, $5, $6::inet,
			$7, $8, $9, $10::public.dfir_tlp, $11, $12,
			$13::public.dfir_malicious_state, $14, $15::jsonb, $16, $16, 1
		)`, uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()),
		string(value.Type()), value.Value(), value.NormalizedValue(), ipValue,
		value.Description(), value.Source(), value.Confidence(), string(value.TLP()),
		value.FirstSeen(), value.LastSeen(), string(value.MaliciousState()), append([]string{}, value.Tags()...),
		nullableJSON(value.Enrichment()), write.Actor.MembershipID)
	return err
}

func updateDFIRIndicator(ctx context.Context, tx databaseTransaction, write application.IndicatorWrite) error {
	value := write.Indicator
	var ipValue any
	if value.Type() == kernel.IndicatorIPv4 || value.Type() == kernel.IndicatorIPv6 {
		ipValue = value.NormalizedValue()
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.dfir_iocs
		SET type = $4::public.dfir_indicator_type, value = $5,
		    normalized_value = $6, ip_value = $7::inet, description = $8,
		    source = $9, confidence = $10, tlp = $11::public.dfir_tlp,
		    first_seen = $12, last_seen = $13,
		    malicious_state = $14::public.dfir_malicious_state,
		    tags = $15, enrichment = $16::jsonb,
		    updated_by_membership_id = $17, version = version + 1,
		    updated_at = transaction_timestamp()
		WHERE tenant_id = $1 AND id = $2 AND version = $3 AND archived_at IS NULL`,
		uuid.UUID(value.TenantID().Bytes()), uuid.UUID(value.ID().Bytes()), int64(write.ExpectedVersion),
		string(value.Type()), value.Value(), value.NormalizedValue(), ipValue,
		value.Description(), value.Source(), value.Confidence(), string(value.TLP()),
		value.FirstSeen(), value.LastSeen(), string(value.MaliciousState()), append([]string{}, value.Tags()...),
		nullableJSON(value.Enrichment()), write.Actor.MembershipID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return application.ErrRepositoryPrecondition
	}
	return nil
}

func (repository *DFIRRepository) CreateAsset(
	ctx context.Context,
	write application.AssetWrite,
) (application.MutationResult[kernel.Asset], error) {
	if !validDFIRCommand(write.Command, "dfir.asset.create") || write.ExpectedVersion != 0 {
		return application.MutationResult[kernel.Asset]{}, application.ErrRepositoryConflict
	}
	return repository.writeAsset(ctx, write, false)
}

func (repository *DFIRRepository) ReplaceAsset(
	ctx context.Context,
	write application.AssetWrite,
) (application.MutationResult[kernel.Asset], error) {
	if !validDFIRCommand(write.Command, "dfir.asset.replace") || write.ExpectedVersion == 0 ||
		write.ExpectedVersion >= kernel.MaximumResourceVersion {
		return application.MutationResult[kernel.Asset]{}, application.ErrRepositoryPrecondition
	}
	return repository.writeAsset(ctx, write, true)
}

func (repository *DFIRRepository) writeAsset(
	ctx context.Context,
	write application.AssetWrite,
	replace bool,
) (application.MutationResult[kernel.Asset], error) {
	if write.AlertID != (kernel.EntityID{}) {
		if write.CaseID != (kernel.EntityID{}) {
			return application.MutationResult[kernel.Asset]{}, application.ErrRepositoryConflict
		}
		return repository.writeAlertAsset(ctx, write, replace)
	}
	if write.CaseID == (kernel.EntityID{}) {
		return application.MutationResult[kernel.Asset]{}, application.ErrRepositoryForbidden
	}
	tenantID := uuid.UUID(write.Asset.TenantID().Bytes())
	caseID := uuid.UUID(write.CaseID.Bytes())
	id := uuid.UUID(write.Asset.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Asset], error) {
			if _, accessErr := authorizeDFIRWrite(ctx, tx, write.Actor, tenantID, application.CapabilityAssetManage, caseID); accessErr != nil {
				return application.MutationResult[kernel.Asset]{}, accessErr
			}
			root := dfirSharedRoot{kind: kernel.EntityCase, id: caseID}
			if replace {
				if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityAsset, id, root); accessErr != nil {
					return application.MutationResult[kernel.Asset]{}, accessErr
				}
			}
			idsNeeded := 4
			if !replace {
				idsNeeded++
			}
			ids, idErr := phase4NewIDs(repository.newID, idsNeeded)
			if idErr != nil {
				return application.MutationResult[kernel.Asset]{}, idErr
			}
			resultVersion := uint64(1)
			if replace {
				resultVersion = write.ExpectedVersion + 1
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindAsset, resourceID: id, resultVersion: resultVersion,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Asset]{}, reserveErr
			}
			if reservation.replayed {
				if !replace {
					if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityAsset, id, root); accessErr != nil {
						return application.MutationResult[kernel.Asset]{}, accessErr
					}
				}
				historical, decodeErr := decodeDFIRAssetResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Asset]{}, decodeErr
				}
				return application.MutationResult[kernel.Asset]{Resource: historical, Replayed: true}, nil
			}
			current, currentVersion, loadErr := loadDFIRAsset(ctx, tx, tenantID, id)
			if loadErr == nil {
				linked, linkErr := dfirResourceLinkedToCase(ctx, tx, "public.dfir_asset_links", "asset_id", tenantID, caseID, id)
				if linkErr != nil {
					return application.MutationResult[kernel.Asset]{}, linkErr
				}
				if !linked {
					return application.MutationResult[kernel.Asset]{}, authorization.ErrForbidden
				}
				if !replace || currentVersion != write.ExpectedVersion {
					return application.MutationResult[kernel.Asset]{}, application.ErrRepositoryPrecondition
				}
			} else if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.MutationResult[kernel.Asset]{}, loadErr
			} else if replace {
				return application.MutationResult[kernel.Asset]{}, pgx.ErrNoRows
			}
			if replace {
				if updateErr := updateDFIRAsset(ctx, tx, write); updateErr != nil {
					return application.MutationResult[kernel.Asset]{}, updateErr
				}
			} else {
				if insertErr := insertDFIRAsset(ctx, tx, write); insertErr != nil {
					return application.MutationResult[kernel.Asset]{}, insertErr
				}
				if _, linkErr := tx.Exec(ctx, `INSERT INTO public.dfir_asset_links
					(id, tenant_id, asset_id, case_id, created_by_membership_id)
					VALUES ($1, $2, $3, $4, $5)`, ids[4], tenantID, id, caseID, write.Actor.MembershipID); linkErr != nil {
					return application.MutationResult[kernel.Asset]{}, linkErr
				}
			}
			version := int64(1)
			action := "dfir.asset.created"
			before := map[string]any{}
			if replace {
				version = int64(write.ExpectedVersion + 1)
				action = "dfir.asset.replaced"
				before = dfirAssetJournal(current, currentVersion)
			}
			kind := string(kernel.EntityAsset)
			if effectErr := appendDFIRMutationEffects(ctx, tx, write.BaseWrite, ids[1:4], phase4MutationEffects{
				PermissionKey: "dfir.asset.manage", Action: action,
				ResourceType: "dfir_asset", ResourceID: id, ResourceVersion: version,
				CaseID: &caseID, ActivityResourceKind: &kind, ActivityResourceID: &id,
				Summary: "DFIR asset changed", Before: before,
				After:    dfirAssetJournal(write.Asset, uint64(version)),
				Metadata: map[string]any{"commandOperation": write.Command.Operation},
			}); effectErr != nil {
				return application.MutationResult[kernel.Asset]{}, effectErr
			}
			stored, storedVersion, storedErr := loadDFIRAsset(ctx, tx, tenantID, id)
			if storedErr != nil || storedVersion != uint64(version) || !sameDFIRAsset(stored, write.Asset) {
				if storedErr != nil {
					return application.MutationResult[kernel.Asset]{}, storedErr
				}
				return application.MutationResult[kernel.Asset]{}, unexpectedDFIRProjection("divergent asset after mutation")
			}
			if activityErr := repository.appendSharedResourceActivities(ctx, tx, reservation.commandID, write.BaseWrite, kernel.EntityAsset, id); activityErr != nil {
				return application.MutationResult[kernel.Asset]{}, activityErr
			}
			document, snapshotErr := encodeDFIRAssetResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Asset]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Asset]{}, storeErr
			}
			return application.MutationResult[kernel.Asset]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

type dfirAssetDatabaseValues struct {
	hostname, normalizedHostname any
	fqdn, normalizedFQDN         any
	ips, macs, mac8s             []string
	original                     []byte
	externalID                   any
	customAttributes             any
}

func dfirAssetValues(value kernel.Asset) (dfirAssetDatabaseValues, error) {
	result := dfirAssetDatabaseValues{
		hostname: optionalSQLString(value.Hostname()), normalizedHostname: optionalSQLString(value.NormalizedHostname()),
		fqdn: optionalSQLString(value.FQDN()), normalizedFQDN: optionalSQLString(value.NormalizedFQDN()),
		externalID: optionalSQLString(value.ExternalID()), customAttributes: nullableJSON(value.CustomAttributes()),
		macs: []string{}, mac8s: []string{},
	}
	addresses := value.IPAddresses()
	result.ips = make([]string, len(addresses))
	originalIPs := make([]string, len(addresses))
	for index, address := range addresses {
		result.ips[index], originalIPs[index] = address.Normalized(), address.Original()
	}
	hardware := value.MACAddresses()
	originalMACs := make([]string, len(hardware))
	for index, address := range hardware {
		originalMACs[index] = address.Original()
		if strings.Count(address.Normalized(), ":") == 5 {
			result.macs = append(result.macs, address.Normalized())
		} else {
			result.mac8s = append(result.mac8s, address.Normalized())
		}
	}
	encoded, err := json.Marshal(dfirOriginalIdentifiers{
		Hostname: optionalStringPointer(value.Hostname()), FQDN: optionalStringPointer(value.FQDN()),
		IPAddresses: originalIPs, MACAddresses: originalMACs,
	})
	if err != nil {
		return dfirAssetDatabaseValues{}, err
	}
	result.original = encoded
	return result, nil
}

func insertDFIRAsset(ctx context.Context, tx databaseTransaction, write application.AssetWrite) error {
	value := write.Asset
	values, err := dfirAssetValues(value)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO public.dfir_assets (
			id, tenant_id, hostname, normalized_hostname, fqdn, normalized_fqdn,
			ip_addresses, mac_addresses, mac8_addresses, original_identifiers,
			asset_type, operating_system, owner, business_unit, criticality,
			environment, external_id, tags, first_seen, last_seen,
			custom_attributes, created_by_membership_id, updated_by_membership_id, version
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7::inet[], $8::macaddr[], $9::macaddr8[], $10::jsonb,
			$11, $12, $13, $14, $15::public.dfir_asset_criticality,
			$16, $17, $18, $19, $20, $21::jsonb, $22, $22, 1
		)`, uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()),
		values.hostname, values.normalizedHostname, values.fqdn, values.normalizedFQDN,
		values.ips, values.macs, values.mac8s, values.original,
		value.AssetType(), value.OperatingSystem(), value.Owner(), value.BusinessUnit(),
		string(value.Criticality()), value.Environment(), values.externalID, append([]string{}, value.Tags()...),
		value.FirstSeen(), value.LastSeen(), values.customAttributes, write.Actor.MembershipID)
	return err
}

func updateDFIRAsset(ctx context.Context, tx databaseTransaction, write application.AssetWrite) error {
	value := write.Asset
	values, err := dfirAssetValues(value)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.dfir_assets
		SET hostname = $4, normalized_hostname = $5, fqdn = $6,
		    normalized_fqdn = $7, ip_addresses = $8::inet[],
		    mac_addresses = $9::macaddr[], mac8_addresses = $10::macaddr8[],
		    original_identifiers = $11::jsonb, asset_type = $12,
		    operating_system = $13, owner = $14, business_unit = $15,
		    criticality = $16::public.dfir_asset_criticality,
		    environment = $17, external_id = $18, tags = $19,
		    first_seen = $20, last_seen = $21, custom_attributes = $22::jsonb,
		    updated_by_membership_id = $23, version = version + 1,
		    updated_at = transaction_timestamp()
		WHERE tenant_id = $1 AND id = $2 AND version = $3 AND archived_at IS NULL`,
		uuid.UUID(value.TenantID().Bytes()), uuid.UUID(value.ID().Bytes()), int64(write.ExpectedVersion),
		values.hostname, values.normalizedHostname, values.fqdn, values.normalizedFQDN,
		values.ips, values.macs, values.mac8s, values.original, value.AssetType(),
		value.OperatingSystem(), value.Owner(), value.BusinessUnit(), string(value.Criticality()),
		value.Environment(), values.externalID, append([]string{}, value.Tags()...), value.FirstSeen(), value.LastSeen(),
		values.customAttributes, write.Actor.MembershipID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return application.ErrRepositoryPrecondition
	}
	return nil
}

func authorizeDFIRWrite(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	caseID uuid.UUID,
) (application.Access, error) {
	if actor.TenantID != tenantID || !authorizationUUIDv7(caseID) {
		return application.Access{}, authorization.ErrForbidden
	}
	access, err := resolveDFIRAccessInTransaction(ctx, tx, actor, tenantID, capability, entityID(caseID))
	if err != nil {
		return application.Access{}, err
	}
	if err := installPersistedTraceContext(ctx, tx); err != nil {
		return application.Access{}, err
	}
	return access, nil
}

func appendDFIRMutationEffects(
	ctx context.Context,
	tx databaseTransaction,
	base application.BaseWrite,
	ids []uuid.UUID,
	effect phase4MutationEffects,
) error {
	if len(ids) != 3 {
		return errors.New("DFIR mutation requires exactly three journal identifiers")
	}
	effect.ActivityID = &ids[0]
	effect.AuditEventID = ids[1]
	effect.OutboxEventID = ids[2]
	effect.RequestID = base.Audit.RequestID
	effect.CorrelationID = base.Audit.CorrelationID
	effect.IPAddress = base.Audit.IPAddress
	effect.UserAgent = base.Audit.UserAgent
	effect.AuthenticationMethod = base.Actor.AuthenticationMethod
	return appendPhase4MutationEffects(ctx, tx, effect)
}

func dfirResourceLinkedToCase(
	ctx context.Context,
	tx databaseTransaction,
	table string,
	resourceColumn string,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	resourceID uuid.UUID,
) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE tenant_id = $1 AND case_id = $2 AND "+resourceColumn+" = $3)", tenantID, caseID, resourceID).Scan(&exists)
	return exists, err
}

func sameDFIRIndicator(left, right kernel.Indicator) bool {
	return left.ID() == right.ID() && left.TenantID() == right.TenantID() &&
		left.Type() == right.Type() && left.Value() == right.Value() &&
		left.NormalizedValue() == right.NormalizedValue() && left.Description() == right.Description() &&
		left.Source() == right.Source() && left.Confidence() == right.Confidence() &&
		left.TLP() == right.TLP() && left.FirstSeen().Equal(right.FirstSeen()) &&
		left.LastSeen().Equal(right.LastSeen()) && left.MaliciousState() == right.MaliciousState() &&
		slices.Equal(left.Tags(), right.Tags()) && slices.Equal(left.Enrichment(), right.Enrichment())
}

func sameDFIRAsset(left, right kernel.Asset) bool {
	leftJSON, leftErr := json.Marshal(dfirAssetComparable(left))
	rightJSON, rightErr := json.Marshal(dfirAssetComparable(right))
	return leftErr == nil && rightErr == nil && slices.Equal(leftJSON, rightJSON)
}

func dfirAssetComparable(value kernel.Asset) map[string]any {
	addresses := value.IPAddresses()
	ips := make([][3]any, len(addresses))
	for index, address := range addresses {
		ips[index] = [3]any{address.Original(), address.Normalized(), address.Family()}
	}
	hardware := value.MACAddresses()
	macs := make([][2]string, len(hardware))
	for index, address := range hardware {
		macs[index] = [2]string{address.Original(), address.Normalized()}
	}
	return map[string]any{
		"id": value.ID().String(), "tenant": value.TenantID().String(),
		"hostname": value.Hostname(), "normalizedHostname": value.NormalizedHostname(),
		"fqdn": value.FQDN(), "normalizedFqdn": value.NormalizedFQDN(),
		"ips": ips, "macs": macs, "type": value.AssetType(), "os": value.OperatingSystem(),
		"owner": value.Owner(), "businessUnit": value.BusinessUnit(),
		"criticality": value.Criticality(), "environment": value.Environment(),
		"externalId": value.ExternalID(), "tags": append([]string{}, value.Tags()...),
		"firstSeen": value.FirstSeen(), "lastSeen": value.LastSeen(),
		"customAttributes": value.CustomAttributes(),
	}
}

func dfirIndicatorJournal(value kernel.Indicator, version uint64) map[string]any {
	return map[string]any{
		"version": version, "type": value.Type(), "confidence": value.Confidence(),
		"tlp": value.TLP(), "maliciousState": value.MaliciousState(),
		"tagCount": len(value.Tags()), "hasEnrichment": len(value.Enrichment()) != 0,
	}
}

func dfirAssetJournal(value kernel.Asset, version uint64) map[string]any {
	return map[string]any{
		"version": version, "criticality": value.Criticality(),
		"ipCount": len(value.IPAddresses()), "macCount": len(value.MACAddresses()),
		"tagCount": len(value.Tags()), "hasExternalId": value.ExternalID() != "",
	}
}

func nullableJSON(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return string(value)
}

func optionalSQLString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
