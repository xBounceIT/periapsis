package postgres

import (
	"bytes"
	"context"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type caseTaskCommandReservation struct {
	commandID uuid.UUID
	resource  uuid.UUID
	version   int64
	snapshot  []byte
	replayed  bool
}

func (repository *DFIRRepository) CommitTask(
	ctx context.Context,
	write application.TaskCreateWrite,
) (application.MutationResult[kernel.Task], error) {
	contract := write.Contract
	value := write.Task
	if !validCaseTaskRepository(repository) ||
		!application.ValidTaskMutationContract(contract, "case.dfir.task.create") ||
		!validDFIRCommand(contract.Command, "case.dfir.task.create") ||
		contract.AlertID != (kernel.EntityID{}) || value.Version() != 1 ||
		value.TenantID().String() != contract.Actor.TenantID.String() ||
		value.CaseID() != contract.CaseID {
		return application.MutationResult[kernel.Task]{}, application.ErrRepositoryConflict
	}
	document, err := encodeCaseTaskResult(value)
	if err != nil {
		return application.MutationResult[kernel.Task]{}, application.ErrRepositoryConflict
	}
	tenantID := contract.Actor.TenantID
	caseID := uuid.UUID(contract.CaseID.Bytes())
	taskID := uuid.UUID(value.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, caseTaskWriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Task], error) {
			if err := authorizeCaseTaskContract(ctx, tx, contract, tenantID, caseID); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			reservation, err := reserveCaseTaskCommand(
				ctx, tx, ids[0], caseID, contract, taskID, 1, document,
			)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			authoritative, err := validateCaseTaskReservation(
				reservation, tenantID, caseID, taskID, 1, true,
			)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			if reservation.replayed {
				if err = validateCaseTaskReferences(ctx, tx, tenantID, caseID, authoritative); err != nil {
					return application.MutationResult[kernel.Task]{}, err
				}
				return application.MutationResult[kernel.Task]{Resource: authoritative, Replayed: true}, nil
			}
			if !sameDFIRTask(authoritative, value) {
				return application.MutationResult[kernel.Task]{}, unexpectedDFIRProjection("Case task reservation changed create snapshot")
			}
			if err = validateCaseTaskReferences(ctx, tx, tenantID, caseID, authoritative); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			epoch, err := resolveDFIRTaskEpoch(
				ctx, tx, tenantID, authoritative.OperatorTeamID(), authoritative.AssigneeID(),
			)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			if err = insertCaseTask(ctx, tx, contract.Actor.MembershipID, authoritative, epoch); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			stored, err := loadDFIRTask(ctx, tx, tenantID, caseID, taskID)
			if err != nil || !sameDFIRTask(stored, authoritative) {
				if err != nil {
					return application.MutationResult[kernel.Task]{}, err
				}
				return application.MutationResult[kernel.Task]{}, unexpectedDFIRProjection("divergent Case task after create")
			}
			if err = appendCaseTaskEffects(
				ctx, tx, contract, taskID, stored.Version(), ids[1:], map[string]any{}, dfirTaskJournal(stored),
			); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			return application.MutationResult[kernel.Task]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) MutateTask(
	ctx context.Context,
	write application.TaskMutationWrite,
) (application.MutationResult[kernel.Task], error) {
	contract := write.Contract
	operation := contract.Command.Operation
	if !validCaseTaskRepository(repository) || !validCaseTaskMutationOperation(operation) ||
		!application.ValidTaskMutationContract(contract, operation) || !validDFIRCommand(contract.Command, operation) ||
		contract.AlertID != (kernel.EntityID{}) || write.Apply == nil || write.TaskID == (kernel.EntityID{}) ||
		write.ExpectedVersion == 0 || write.ExpectedVersion >= kernel.MaximumAlertResourceVersion {
		return application.MutationResult[kernel.Task]{}, application.ErrRepositoryPrecondition
	}
	tenantID := contract.Actor.TenantID
	caseID := uuid.UUID(contract.CaseID.Bytes())
	taskID := uuid.UUID(write.TaskID.Bytes())
	resultVersion := int64(write.ExpectedVersion + 1)
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, caseTaskWriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Task], error) {
			if err := authorizeCaseTaskContract(ctx, tx, contract, tenantID, caseID); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			reservation, err := reserveCaseTaskCommand(
				ctx, tx, ids[0], caseID, contract, taskID, resultVersion, nil,
			)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			if reservation.replayed {
				replayed, validationErr := validateCaseTaskReservation(
					reservation, tenantID, caseID, taskID, resultVersion, true,
				)
				if validationErr != nil {
					return application.MutationResult[kernel.Task]{}, validationErr
				}
				if validationErr = validateCaseTaskReferences(ctx, tx, tenantID, caseID, replayed); validationErr != nil {
					return application.MutationResult[kernel.Task]{}, validationErr
				}
				return application.MutationResult[kernel.Task]{Resource: replayed, Replayed: true}, nil
			}
			if _, validationErr := validateCaseTaskReservation(
				reservation, tenantID, caseID, taskID, resultVersion, false,
			); validationErr != nil {
				return application.MutationResult[kernel.Task]{}, validationErr
			}

			var epoch *uuid.UUID
			if err = tx.QueryRow(ctx, `SELECT operator_team_epoch_id
				FROM public.dfir_tasks
				WHERE tenant_id=$1 AND case_id=$2 AND alert_id IS NULL AND id=$3
				FOR UPDATE`, tenantID, caseID, taskID).Scan(&epoch); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}

			reservation, err = reserveCaseTaskCommand(
				ctx, tx, ids[0], caseID, contract, taskID, resultVersion, nil,
			)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			if reservation.replayed {
				replayed, validationErr := validateCaseTaskReservation(
					reservation, tenantID, caseID, taskID, resultVersion, true,
				)
				if validationErr != nil {
					return application.MutationResult[kernel.Task]{}, validationErr
				}
				if validationErr = validateCaseTaskReferences(ctx, tx, tenantID, caseID, replayed); validationErr != nil {
					return application.MutationResult[kernel.Task]{}, validationErr
				}
				return application.MutationResult[kernel.Task]{Resource: replayed, Replayed: true}, nil
			}
			if _, validationErr := validateCaseTaskReservation(
				reservation, tenantID, caseID, taskID, resultVersion, false,
			); validationErr != nil {
				return application.MutationResult[kernel.Task]{}, validationErr
			}

			current, err := loadDFIRTask(ctx, tx, tenantID, caseID, taskID)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			if current.Version() != write.ExpectedVersion {
				return application.MutationResult[kernel.Task]{}, application.ErrRepositoryPrecondition
			}
			updated, err := write.Apply(current)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			if !validCaseTaskMutation(current, updated, operation, write.ExpectedVersion) {
				return application.MutationResult[kernel.Task]{}, application.ErrRepositoryConflict
			}
			if operation == "case.dfir.task.assign" {
				epoch, err = resolveDFIRTaskEpoch(ctx, tx, tenantID, updated.OperatorTeamID(), updated.AssigneeID())
				if err != nil {
					return application.MutationResult[kernel.Task]{}, err
				}
			}
			if err = validateCaseTaskReferences(ctx, tx, tenantID, caseID, updated); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			document, err := encodeCaseTaskResult(updated)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			reservation, err = reserveCaseTaskCommand(
				ctx, tx, ids[0], caseID, contract, taskID, resultVersion, document,
			)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			authoritative, err := validateCaseTaskReservation(
				reservation, tenantID, caseID, taskID, resultVersion, true,
			)
			if err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			if reservation.replayed || !sameDFIRTask(authoritative, updated) {
				return application.MutationResult[kernel.Task]{}, unexpectedDFIRProjection("Case task reservation changed mutation snapshot")
			}
			if err = updateCaseTask(
				ctx, tx, contract.Actor.MembershipID, authoritative, write.ExpectedVersion, epoch,
			); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			stored, err := loadDFIRTask(ctx, tx, tenantID, caseID, taskID)
			if err != nil || !sameDFIRTask(stored, authoritative) {
				if err != nil {
					return application.MutationResult[kernel.Task]{}, err
				}
				return application.MutationResult[kernel.Task]{}, unexpectedDFIRProjection("divergent Case task after mutation")
			}
			if err = appendCaseTaskEffects(
				ctx, tx, contract, taskID, stored.Version(), ids[1:], dfirTaskJournal(current), dfirTaskJournal(stored),
			); err != nil {
				return application.MutationResult[kernel.Task]{}, err
			}
			return application.MutationResult[kernel.Task]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func caseTaskWriteOptions() pgx.TxOptions {
	return pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
}

func validCaseTaskRepository(repository *DFIRRepository) bool {
	return repository != nil && repository.begin != nil && repository.newID != nil
}

func authorizeCaseTaskContract(
	ctx context.Context,
	tx databaseTransaction,
	contract application.TaskMutationContract,
	tenantID uuid.UUID,
	caseID uuid.UUID,
) error {
	access, err := authorizeDFIRWrite(ctx, tx, contract.Actor, tenantID, contract.Capability, caseID)
	if err != nil {
		return err
	}
	if !sameDFIRAccess(access, contract.Access) {
		return authorization.ErrForbidden
	}
	return nil
}

func reserveCaseTaskCommand(
	ctx context.Context,
	tx databaseTransaction,
	commandID uuid.UUID,
	caseID uuid.UUID,
	contract application.TaskMutationContract,
	resourceID uuid.UUID,
	resultVersion int64,
	snapshot []byte,
) (caseTaskCommandReservation, error) {
	var result caseTaskCommandReservation
	err := tx.QueryRow(ctx, `SELECT command_id, result_resource_id, result_version,
		result_snapshot, replayed
		FROM app.reserve_case_dfir_command_v1($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
		commandID, caseID, contract.Command.Operation, resourceID, resultVersion,
		contract.Command.KeyDigest[:], contract.Command.RequestDigest[:], nullableJSON(snapshot),
	).Scan(&result.commandID, &result.resource, &result.version, &result.snapshot, &result.replayed)
	return result, err
}

func validateCaseTaskReservation(
	reservation caseTaskCommandReservation,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	taskID uuid.UUID,
	version int64,
	requireSnapshot bool,
) (kernel.Task, error) {
	if reservation.commandID == uuid.Nil || reservation.resource != taskID ||
		reservation.version != version || reservation.replayed && !requireSnapshot {
		return kernel.Task{}, unexpectedDFIRProjection("Case task command reservation coordinate mismatch")
	}
	if !requireSnapshot {
		if len(reservation.snapshot) != 0 || reservation.replayed {
			return kernel.Task{}, unexpectedDFIRProjection("Case task lookup miss returned a snapshot")
		}
		return kernel.Task{}, nil
	}
	value, err := decodeCaseTaskResult(reservation.snapshot)
	if err != nil {
		return kernel.Task{}, err
	}
	if uuid.UUID(value.TenantID().Bytes()) != tenantID || uuid.UUID(value.CaseID().Bytes()) != caseID ||
		uuid.UUID(value.ID().Bytes()) != taskID || int64(value.Version()) != version {
		return kernel.Task{}, unexpectedDFIRProjection("Case task replay snapshot coordinate mismatch")
	}
	return value, nil
}

func appendCaseTaskEffects(
	ctx context.Context,
	tx databaseTransaction,
	contract application.TaskMutationContract,
	taskID uuid.UUID,
	version uint64,
	ids []uuid.UUID,
	before any,
	after any,
) error {
	caseID := uuid.UUID(contract.CaseID.Bytes())
	kind := string(kernel.EntityTask)
	return appendDFIRMutationEffects(ctx, tx, contract.BaseWrite, ids, phase4MutationEffects{
		PermissionKey: string(contract.Capability), Action: contract.AuditAction,
		ResourceType: "dfir_task", ResourceID: taskID, ResourceVersion: int64(version),
		CaseID: &caseID, ActivityResourceKind: &kind, ActivityResourceID: &taskID,
		Summary: contract.ActivitySummary, Before: before, After: after,
		Metadata: map[string]any{
			"commandOperation": contract.Command.Operation,
			"reason":           contract.AuditReason,
		},
	})
}

func validCaseTaskMutationOperation(operation string) bool {
	switch operation {
	case "case.dfir.task.transition", "case.dfir.task.replace_details",
		"case.dfir.task.assign", "case.dfir.task.reschedule",
		"case.dfir.task.replace_checklist", "case.dfir.task.comments.replace":
		return true
	default:
		return false
	}
}

func validCaseTaskMutation(current, updated kernel.Task, operation string, expectedVersion uint64) bool {
	if current.ID() != updated.ID() || current.TenantID() != updated.TenantID() ||
		current.CaseID() != updated.CaseID() || current.Version() != expectedVersion ||
		updated.Version() != expectedVersion+1 ||
		!current.CreatedAt().Equal(updated.CreatedAt()) || updated.UpdatedAt().Before(current.UpdatedAt()) {
		return false
	}
	sameDetails := current.Title() == updated.Title() && current.Description() == updated.Description() &&
		current.Priority() == updated.Priority() &&
		sameOptionalKernelID(current.SLAInstanceID(), updated.SLAInstanceID())
	sameAssignment := sameOptionalKernelID(current.AssigneeID(), updated.AssigneeID()) &&
		sameOptionalKernelID(current.OperatorTeamID(), updated.OperatorTeamID())
	sameDue := sameOptionalTime(current.DueAt(), updated.DueAt())
	leftChecklist, leftErr := encodeDFIRChecklist(current.Checklist())
	rightChecklist, rightErr := encodeDFIRChecklist(updated.Checklist())
	sameChecklist := leftErr == nil && rightErr == nil && bytes.Equal(leftChecklist, rightChecklist)
	sameCompletion := current.Status() == updated.Status() &&
		sameOptionalTime(current.CompletedAt(), updated.CompletedAt()) &&
		sameOptionalKernelID(current.CompletedBy(), updated.CompletedBy()) &&
		bytes.Equal(current.CompletionData(), updated.CompletionData())
	sameComments := slices.Equal(current.CommentIDs(), updated.CommentIDs())
	switch operation {
	case "case.dfir.task.transition":
		return sameDetails && sameAssignment && sameDue && sameChecklist && sameComments
	case "case.dfir.task.replace_details":
		return sameAssignment && sameDue && sameChecklist && sameCompletion && sameComments
	case "case.dfir.task.assign":
		return sameDetails && sameDue && sameChecklist && sameCompletion && sameComments
	case "case.dfir.task.reschedule":
		return sameDetails && sameAssignment && sameChecklist && sameCompletion && sameComments
	case "case.dfir.task.replace_checklist":
		return sameDetails && sameAssignment && sameDue && sameCompletion && sameComments
	case "case.dfir.task.comments.replace":
		return sameDetails && sameAssignment && sameDue && sameChecklist && sameCompletion && !sameComments
	default:
		return false
	}
}

func validateCaseTaskReferences(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	value kernel.Task,
) error {
	if comments := value.CommentIDs(); len(comments) != 0 {
		var count int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.ticket_comments
			WHERE tenant_id=$1 AND case_id=$2 AND alert_id IS NULL AND id=ANY($3::uuid[])`,
			tenantID, caseID, kernelUUIDs(comments),
		).Scan(&count); err != nil {
			return err
		}
		if count != int64(len(comments)) {
			return authorization.ErrForbidden
		}
	}
	if sla := value.SLAInstanceID(); sla != nil {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.sla_instances
			WHERE tenant_id=$1 AND id=$2 AND object_type='case' AND object_id=$3)`,
			tenantID, uuid.UUID(sla.Bytes()), caseID,
		).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return authorization.ErrForbidden
		}
	}
	return nil
}

func insertCaseTask(
	ctx context.Context,
	tx databaseTransaction,
	membershipID uuid.UUID,
	value kernel.Task,
	epoch *uuid.UUID,
) error {
	checklist, err := encodeDFIRChecklist(value.Checklist())
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.dfir_tasks (
		id, tenant_id, alert_id, case_id, title, description, status, priority,
		assignee_user_id, operator_team_id, operator_team_epoch_id, due_at, checklist,
		completed_at, completed_by_user_id, completion_data, comment_ids, sla_instance_id,
		created_by_membership_id, created_by_service_account_id,
		updated_by_membership_id, updated_by_service_account_id, version, created_at, updated_at
	) VALUES ($1,$2,NULL,$3,$4,$5,$6::public.dfir_task_status,$7::public.dfir_task_priority,
		$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb,$16,$17,$18,NULL,$18,NULL,$19,$20,$21)`,
		uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()), uuid.UUID(value.CaseID().Bytes()),
		value.Title(), value.Description(), string(value.Status()), string(value.Priority()), optionalKernelUUID(value.AssigneeID()),
		optionalKernelUUID(value.OperatorTeamID()), epoch, value.DueAt(), checklist, value.CompletedAt(),
		optionalKernelUUID(value.CompletedBy()), nullableJSON(value.CompletionData()), kernelUUIDs(value.CommentIDs()),
		optionalKernelUUID(value.SLAInstanceID()), membershipID, int64(value.Version()), value.CreatedAt(), value.UpdatedAt())
	return err
}

func updateCaseTask(
	ctx context.Context,
	tx databaseTransaction,
	membershipID uuid.UUID,
	value kernel.Task,
	expectedVersion uint64,
	epoch *uuid.UUID,
) error {
	checklist, err := encodeDFIRChecklist(value.Checklist())
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.dfir_tasks SET
		title=$5, description=$6, status=$7::public.dfir_task_status, priority=$8::public.dfir_task_priority,
		assignee_user_id=$9, operator_team_id=$10, operator_team_epoch_id=$11, due_at=$12,
		checklist=$13::jsonb, completed_at=$14, completed_by_user_id=$15, completion_data=$16::jsonb,
		comment_ids=$17, sla_instance_id=$18, updated_by_membership_id=$19,
		updated_by_service_account_id=NULL, version=$20, updated_at=$21
		WHERE tenant_id=$1 AND case_id=$2 AND alert_id IS NULL AND id=$3 AND version=$4`,
		uuid.UUID(value.TenantID().Bytes()), uuid.UUID(value.CaseID().Bytes()), uuid.UUID(value.ID().Bytes()), int64(expectedVersion),
		value.Title(), value.Description(), string(value.Status()), string(value.Priority()), optionalKernelUUID(value.AssigneeID()),
		optionalKernelUUID(value.OperatorTeamID()), epoch, value.DueAt(), checklist, value.CompletedAt(), optionalKernelUUID(value.CompletedBy()),
		nullableJSON(value.CompletionData()), kernelUUIDs(value.CommentIDs()), optionalKernelUUID(value.SLAInstanceID()),
		membershipID, int64(value.Version()), value.UpdatedAt())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return application.ErrRepositoryPrecondition
	}
	return nil
}
