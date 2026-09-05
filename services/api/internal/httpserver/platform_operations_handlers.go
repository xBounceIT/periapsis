package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoperations"
)

const platformOperationsDefaultPageSize = int32(50)

type platformFailedNotificationCursorWire struct {
	Version   int    `json:"v"`
	FailureAt string `json:"failureAt"`
	ID        string `json:"id"`
}

func (h *Handler) ListPlatformUsers(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformUsersParams,
) {
	session, event, ok := h.platformOperationsRead(w, r)
	if !ok {
		return
	}
	input := platformoperations.ListUsersInput{Limit: platformOperationsPageSize(params.Limit), Event: event}
	if params.After != nil {
		value := uuid.UUID(*params.After)
		input.After = &value
	}
	page, err := h.platformOperations.ListUsers(r.Context(), session, input)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformUserPage(page)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

func (h *Handler) GetPlatformGlobalSettings(w http.ResponseWriter, r *http.Request) {
	session, event, ok := h.platformOperationsRead(w, r)
	if !ok {
		return
	}
	settings, err := h.platformOperations.GetSettings(
		r.Context(), session, platformoperations.ReadInput{Event: event},
	)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformGlobalSettings(settings)
	if err != nil || !setVersionETag(w, int64(settings.Version)) {
		h.writePlatformOperationsError(w, r, platformoperations.ErrUnavailable)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

func (h *Handler) UpdatePlatformGlobalSettings(
	w http.ResponseWriter,
	r *http.Request,
	params contract.UpdatePlatformGlobalSettingsParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return
	}
	var body contract.PlatformGlobalSettingsUpdateRequest
	if err := decodePlatformGlobalSettingsUpdateBody(r, &body); err != nil {
		h.writePlatformOperationsError(w, r, platformoperations.ErrInvalidInput)
		return
	}
	expectedVersion, ok := platformOperationsPrecondition(w, r, params.IfMatch, body.ExpectedVersion)
	if !ok {
		return
	}
	reason, err := platformOperationsAuditReason(r, params.XAuditReason)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writePlatformOperationsError(w, r, platformoperations.ErrInvalidInput)
		return
	}
	settings, err := h.platformOperations.UpdateSettings(
		r.Context(), session, platformoperations.UpdateSettingsInput{
			ExpectedVersion: expectedVersion,
			PlatformName:    body.PlatformName, DefaultLocale: body.DefaultLocale,
			DefaultTimezone: body.DefaultTimezone, SupportURL: body.SupportUrl,
			Reason: reason, Event: event,
		},
	)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformGlobalSettings(settings)
	if err != nil || settings.Version != expectedVersion+1 ||
		!setVersionETag(w, int64(settings.Version)) {
		h.writePlatformOperationsError(w, r, platformoperations.ErrUnavailable)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

// decodePlatformGlobalSettingsUpdateBody preserves the strict authorization
// decoder's transport guarantees while accepting the one explicit nullable
// field in this request. The shared decoder deliberately rejects every JSON
// null and therefore cannot represent clearing supportUrl.
func decodePlatformGlobalSettingsUpdateBody(
	r *http.Request,
	destination *contract.PlatformGlobalSettingsUpdateRequest,
) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return errors.New("unsupported request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 1<<20 || !utf8.Valid(body) {
		return errors.New("request body is invalid")
	}
	if !validJSONUnicodeScalarEscapes(body) {
		return errors.New("request body contains an unpaired Unicode surrogate")
	}
	if err := validatePlatformGlobalSettingsUpdateTokens(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func validatePlatformGlobalSettingsUpdateTokens(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("request body must be an object")
	}
	required := map[string]bool{
		"defaultLocale": false, "defaultTimezone": false, "expectedVersion": false,
		"platformName": false, "supportUrl": false,
	}
	for decoder.More() {
		keyToken, keyErr := decoder.Token()
		key, ok := keyToken.(string)
		seen, known := required[key]
		if keyErr != nil || !ok || !known || seen || containsJSONControlCharacter(key) {
			return errors.New("request body contains an invalid or duplicate field")
		}
		required[key] = true
		value, valueErr := decoder.Token()
		if valueErr != nil || !platformGlobalSettingsUpdateTokenValid(key, value) {
			return errors.New("request body contains an invalid field value")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("request body is incomplete")
	}
	for _, seen := range required {
		if !seen {
			return errors.New("request body is missing a required field")
		}
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func platformGlobalSettingsUpdateTokenValid(key string, value any) bool {
	if key == "supportUrl" && value == nil {
		return true
	}
	switch key {
	case "defaultLocale", "defaultTimezone", "platformName", "supportUrl":
		text, ok := value.(string)
		return ok && !containsJSONControlCharacter(text)
	case "expectedVersion":
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}

func (h *Handler) GetPlatformOperationsHealth(w http.ResponseWriter, r *http.Request) {
	session, event, ok := h.platformOperationsRead(w, r)
	if !ok {
		return
	}
	health, err := h.platformOperations.GetHealth(
		r.Context(), session, platformoperations.ReadInput{Event: event},
	)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformOperationsHealth(health)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

func (h *Handler) ListPlatformOperationQueues(w http.ResponseWriter, r *http.Request) {
	session, event, ok := h.platformOperationsRead(w, r)
	if !ok {
		return
	}
	snapshot, err := h.platformOperations.ListQueues(
		r.Context(), session, platformoperations.ReadInput{Event: event},
	)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformOperationQueues(snapshot)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

func (h *Handler) ListPlatformFailedNotifications(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformFailedNotificationsParams,
) {
	session, event, ok := h.platformOperationsRead(w, r)
	if !ok {
		return
	}
	input := platformoperations.ListFailedNotificationsInput{
		Limit: platformOperationsPageSize(params.Limit), Event: event,
	}
	if params.After != nil {
		cursor, err := decodePlatformFailedNotificationCursor(string(*params.After))
		if err != nil {
			h.writePlatformOperationsError(w, r, err)
			return
		}
		input.After = &cursor
	}
	page, err := h.platformOperations.ListFailedNotifications(r.Context(), session, input)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformFailedNotificationPage(page)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

func (h *Handler) ListPlatformFeatureFlags(w http.ResponseWriter, r *http.Request) {
	session, event, ok := h.platformOperationsRead(w, r)
	if !ok {
		return
	}
	flags, err := h.platformOperations.ListFeatureFlags(
		r.Context(), session, platformoperations.ReadInput{Event: event},
	)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformFeatureFlagList(flags)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

func (h *Handler) UpdatePlatformFeatureFlag(
	w http.ResponseWriter,
	r *http.Request,
	flagKey contract.PlatformFeatureFlagKey,
	params contract.UpdatePlatformFeatureFlagParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return
	}
	var body contract.PlatformFeatureFlagUpdateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writePlatformOperationsError(w, r, platformoperations.ErrInvalidInput)
		return
	}
	expectedVersion, ok := platformOperationsPrecondition(w, r, params.IfMatch, body.ExpectedVersion)
	if !ok {
		return
	}
	reason, err := platformOperationsAuditReason(r, params.XAuditReason)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writePlatformOperationsError(w, r, platformoperations.ErrInvalidInput)
		return
	}
	flag, err := h.platformOperations.UpdateFeatureFlag(
		r.Context(), session, platformoperations.UpdateFeatureFlagInput{
			Key: string(flagKey), ExpectedVersion: expectedVersion,
			Enabled: body.Enabled, Reason: reason, Event: event,
		},
	)
	if err != nil {
		h.writePlatformOperationsError(w, r, err)
		return
	}
	response, err := mapPlatformFeatureFlag(flag)
	if err != nil || flag.Version != expectedVersion+1 ||
		!setVersionETag(w, int64(flag.Version)) {
		h.writePlatformOperationsError(w, r, platformoperations.ErrUnavailable)
		return
	}
	writePlatformOperationsJSON(w, http.StatusOK, response)
}

func (h *Handler) platformOperationsRead(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, authentication.EventContext, bool) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return authentication.Session{}, authentication.EventContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writePlatformOperationsError(w, r, platformoperations.ErrInvalidInput)
		return authentication.Session{}, authentication.EventContext{}, false
	}
	return session, event, true
}

func platformOperationsPageSize(value *contract.PageSize) int32 {
	if value == nil {
		return platformOperationsDefaultPageSize
	}
	return int32(*value)
}

func platformOperationsPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue contract.IfMatch,
	bodyVersion int32,
) (int32, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required", "A current strong If-Match entity tag is required.")
		return 0, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || canonical != string(contractValue) ||
		int64(bodyVersion) != version || version < 1 || version >= math.MaxInt32 {
		writePlatformOperationsDomainError(w, r, platformoperations.ErrInvalidInput)
		return 0, false
	}
	return int32(version), true
}

func platformOperationsAuditReason(
	r *http.Request,
	contractValue contract.PlatformOperationsAuditReason,
) (string, error) {
	reason, err := singleHeader(r, "X-Audit-Reason", 500)
	if err != nil || reason != string(contractValue) ||
		!platformIdentityProviderAuditReasonIsHTTPValue(reason) {
		return "", platformoperations.ErrInvalidInput
	}
	return reason, nil
}

func mapPlatformUserPage(page platformoperations.UserPage) (contract.PlatformUserPage, error) {
	response := contract.PlatformUserPage{
		ProjectionVersion: contract.PlatformOperationsProjectionVersion(page.ProjectionVersion),
		Items:             make([]contract.PlatformUserInventoryItem, 0, len(page.Items)),
	}
	if !response.ProjectionVersion.Valid() {
		return contract.PlatformUserPage{}, platformoperations.ErrUnavailable
	}
	for _, user := range page.Items {
		item := contract.PlatformUserInventoryItem{
			Id: user.ID, DisplayName: user.DisplayName, Active: user.Active,
			PlatformRoles:               append([]string(nil), user.PlatformRoles...),
			ActiveTenantMembershipCount: user.ActiveTenantMembershipCount,
			TotalTenantMembershipCount:  user.TotalTenantMembershipCount,
			LiveSessionsByAuthenticationMethod: make(
				[]contract.PlatformLiveSessionMethodSummary, 0,
				len(user.LiveSessionsByAuthenticationMethod),
			),
		}
		if user.Email != nil {
			email := openapi_types.Email(*user.Email)
			item.Email = &email
		}
		for _, summary := range user.LiveSessionsByAuthenticationMethod {
			method := contract.SessionAuthenticationMethod(summary.Method)
			if !method.Valid() {
				return contract.PlatformUserPage{}, platformoperations.ErrUnavailable
			}
			item.LiveSessionsByAuthenticationMethod = append(
				item.LiveSessionsByAuthenticationMethod,
				contract.PlatformLiveSessionMethodSummary{
					Method: method, LiveSessionCount: summary.LiveSessionCount,
				},
			)
		}
		response.Items = append(response.Items, item)
	}
	if page.NextCursor != nil {
		cursor := openapi_types.UUID(*page.NextCursor)
		response.NextCursor = &cursor
	}
	return response, nil
}

func mapPlatformGlobalSettings(
	settings platformoperations.GlobalSettings,
) (contract.PlatformGlobalSettings, error) {
	if settings.Version < 1 || settings.UpdatedAt.IsZero() {
		return contract.PlatformGlobalSettings{}, platformoperations.ErrUnavailable
	}
	return contract.PlatformGlobalSettings{
		PlatformName: settings.PlatformName, DefaultLocale: settings.DefaultLocale,
		DefaultTimezone: settings.DefaultTimezone, SupportUrl: settings.SupportURL,
		Version: contract.ResourceVersion(settings.Version), UpdatedAt: settings.UpdatedAt,
	}, nil
}

func mapPlatformOperationQueues(
	snapshot platformoperations.QueueSnapshot,
) (contract.PlatformOperationQueueSnapshot, error) {
	response := contract.PlatformOperationQueueSnapshot{
		ProjectionVersion: contract.PlatformOperationsProjectionVersion(snapshot.ProjectionVersion),
		CheckedAt:         snapshot.CheckedAt,
		Sources:           make([]contract.PlatformOperationQueueSource, 0, len(snapshot.Sources)),
	}
	if !response.ProjectionVersion.Valid() || response.CheckedAt.IsZero() {
		return contract.PlatformOperationQueueSnapshot{}, platformoperations.ErrUnavailable
	}
	for _, source := range snapshot.Sources {
		key := contract.PlatformOperationQueueKey(source.Key)
		if !key.Valid() {
			return contract.PlatformOperationQueueSnapshot{}, platformoperations.ErrUnavailable
		}
		response.Sources = append(response.Sources, contract.PlatformOperationQueueSource{
			Key: key, PendingCount: source.PendingCount, InFlightCount: source.InFlightCount,
			FailedCount: source.FailedCount, OldestPendingSeconds: source.OldestPendingSeconds,
		})
	}
	return response, nil
}

func mapPlatformOperationsHealth(
	health platformoperations.Health,
) (contract.PlatformOperationsHealth, error) {
	response := contract.PlatformOperationsHealth{
		ProjectionVersion: contract.PlatformOperationsProjectionVersion(health.ProjectionVersion),
		CheckedAt:         health.CheckedAt, Status: contract.PlatformHealthStatus(health.Status),
		Checks: make([]contract.PlatformOperationsHealthCheck, 0, len(health.Checks)),
	}
	if !response.ProjectionVersion.Valid() || !response.Status.Valid() || response.CheckedAt.IsZero() {
		return contract.PlatformOperationsHealth{}, platformoperations.ErrUnavailable
	}
	for _, check := range health.Checks {
		key := contract.PlatformOperationsHealthCheckKey(check.Key)
		status := contract.PlatformHealthStatus(check.Status)
		if !key.Valid() || !status.Valid() {
			return contract.PlatformOperationsHealth{}, platformoperations.ErrUnavailable
		}
		response.Checks = append(response.Checks, contract.PlatformOperationsHealthCheck{
			Key: key, Status: status, PendingCount: check.PendingCount,
			FailedCount: check.FailedCount, OldestPendingSeconds: check.OldestPendingSeconds,
		})
	}
	return response, nil
}

func mapPlatformFailedNotificationPage(
	page platformoperations.FailedNotificationPage,
) (contract.PlatformFailedNotificationPage, error) {
	response := contract.PlatformFailedNotificationPage{
		ProjectionVersion: contract.PlatformOperationsProjectionVersion(page.ProjectionVersion),
		Items:             make([]contract.PlatformFailedNotification, 0, len(page.Items)),
	}
	if !response.ProjectionVersion.Valid() {
		return contract.PlatformFailedNotificationPage{}, platformoperations.ErrUnavailable
	}
	for _, item := range page.Items {
		channel := contract.PlatformFailedNotificationChannel(item.Channel)
		class := contract.PlatformFailedNotificationFailureClass(item.FailureClass)
		code := contract.PlatformFailedNotificationFailureCode(item.FailureCode)
		if !channel.Valid() || !class.Valid() || !code.Valid() {
			return contract.PlatformFailedNotificationPage{}, platformoperations.ErrUnavailable
		}
		response.Items = append(response.Items, contract.PlatformFailedNotification{
			Id: item.ID, TenantId: item.TenantID, Channel: channel,
			FailureClass: class, FailureCode: code, FailureAt: item.FailureAt,
			CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt, AttemptCount: item.AttemptCount,
		})
	}
	if page.NextCursor != nil {
		cursor, err := encodePlatformFailedNotificationCursor(*page.NextCursor)
		if err != nil {
			return contract.PlatformFailedNotificationPage{}, err
		}
		response.NextCursor = &cursor
	}
	return response, nil
}

func mapPlatformFeatureFlagList(
	flags platformoperations.FeatureFlagList,
) (contract.PlatformFeatureFlagList, error) {
	response := contract.PlatformFeatureFlagList{
		ProjectionVersion: contract.PlatformOperationsProjectionVersion(flags.ProjectionVersion),
		Items:             make([]contract.PlatformFeatureFlag, 0, len(flags.Items)),
	}
	if !response.ProjectionVersion.Valid() {
		return contract.PlatformFeatureFlagList{}, platformoperations.ErrUnavailable
	}
	for _, flag := range flags.Items {
		item, err := mapPlatformFeatureFlag(flag)
		if err != nil {
			return contract.PlatformFeatureFlagList{}, err
		}
		response.Items = append(response.Items, item)
	}
	return response, nil
}

func mapPlatformFeatureFlag(flag platformoperations.FeatureFlag) (contract.PlatformFeatureFlag, error) {
	key := contract.PlatformFeatureFlagKey(flag.Key)
	if !key.Valid() || flag.Version < 1 || flag.UpdatedAt.IsZero() {
		return contract.PlatformFeatureFlag{}, platformoperations.ErrUnavailable
	}
	return contract.PlatformFeatureFlag{
		Key: key, Enabled: flag.Enabled, Version: contract.ResourceVersion(flag.Version),
		UpdatedAt: flag.UpdatedAt,
	}, nil
}

func encodePlatformFailedNotificationCursor(
	cursor platformoperations.FailedNotificationCursor,
) (string, error) {
	if cursor.ID == uuid.Nil || cursor.FailureAt.IsZero() {
		return "", platformoperations.ErrUnavailable
	}
	document, err := json.Marshal(platformFailedNotificationCursorWire{
		Version: 1, FailureAt: cursor.FailureAt.UTC().Format(time.RFC3339Nano),
		ID: cursor.ID.String(),
	})
	if err != nil {
		return "", platformoperations.ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(document), nil
}

func decodePlatformFailedNotificationCursor(
	value string,
) (platformoperations.FailedNotificationCursor, error) {
	if value == "" || len(value) > 512 {
		return platformoperations.FailedNotificationCursor{}, platformoperations.ErrInvalidInput
	}
	document, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(document) != value || len(document) > 384 {
		return platformoperations.FailedNotificationCursor{}, platformoperations.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire platformFailedNotificationCursorWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Version != 1 {
		return platformoperations.FailedNotificationCursor{}, platformoperations.ErrInvalidInput
	}
	failureAt, err := time.Parse(time.RFC3339Nano, wire.FailureAt)
	if err != nil || wire.FailureAt != failureAt.UTC().Format(time.RFC3339Nano) {
		return platformoperations.FailedNotificationCursor{}, platformoperations.ErrInvalidInput
	}
	id, err := uuid.Parse(wire.ID)
	if err != nil || wire.ID != id.String() || id.Version() != 7 || id.Variant() != uuid.RFC4122 {
		return platformoperations.FailedNotificationCursor{}, platformoperations.ErrInvalidInput
	}
	return platformoperations.FailedNotificationCursor{FailureAt: failureAt, ID: id}, nil
}

func writePlatformOperationsJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, status, value)
}

func (h *Handler) writePlatformOperationsError(w http.ResponseWriter, r *http.Request, err error) {
	writePlatformOperationsDomainError(w, r, err)
}

func writePlatformOperationsDomainError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		if errors.Is(r.Context().Err(), context.Canceled) {
			return
		}
		err = platformoperations.ErrUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = platformoperations.ErrUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, platformoperations.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The request is malformed or fails bounded validation.")
	case errors.Is(err, platformoperations.ErrForbidden), errors.Is(err, authentication.ErrForbidden):
		writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The action is not permitted.")
	case errors.Is(err, platformoperations.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The requested resource does not exist.")
	case errors.Is(err, platformoperations.ErrConflict):
		writeProblem(w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed", "The resource changed after the supplied entity tag was issued.")
	case errors.Is(err, platformoperations.ErrUnavailable):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required protected dependency is unavailable.")
	default:
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
	}
}
