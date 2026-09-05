package federatedsaml

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"mime"
	"net/url"
	"slices"
	"strings"
	"time"
)

type parsedResponse struct {
	id               string
	issuer           string
	destination      string
	inResponseTo     string
	issueInstant     time.Time
	hasSignature     bool
	assertion        *xmlNode
	encrypted        bool
	encryptedID      string
	contentAlgorithm string
	keyAlgorithm     string
	keyDigest        string
	keyMGF           string
}

func (kernel *Kernel) ValidateCallback(ctx context.Context, request CallbackRequest) (*ValidatedAuthentication, error) {
	if kernel == nil || kernel.transactions == nil || request.Configuration.Authority != kernel.authority ||
		!validBrowserHandle(request.BrowserHandle) {
		return nil, ErrCallbackRejected
	}
	now, err := canonicalNow(kernel.now)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	configuration, configurationDigest, err := normalizeConfiguration(request.Configuration, now, kernel.limits)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	responseDocument, relayState, err := parsePOSTForm(request.MediaType, request.RawForm, kernel.limits)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	defer clear(responseDocument)
	bounded, cancel, err := operationContext(ctx, kernel.operationTimeout)
	if err != nil {
		return nil, errors.Join(ErrCallbackRejected, err)
	}
	defer cancel()
	pending, err := kernel.transactions.Lookup(bounded, LookupTransactionRequest{
		RelayStateDigest: digestOpaque([]byte(relayState)), BrowserDigest: digestOpaque(request.BrowserHandle),
		ObservedAt: now,
	})
	relayDigest := digestOpaque([]byte(relayState))
	browserDigest := digestOpaque(request.BrowserHandle)
	if err != nil || !validPendingTransaction(pending, now, relayDigest, browserDigest, transactionPins(configuration, configurationDigest)) {
		return nil, ErrCallbackRejected
	}
	root, err := parseBoundedXML(responseDocument, kernel.limits.MaxDecodedResponseBytes, kernel.limits)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	response, err := parseResponse(root)
	if err != nil || response.issuer != configuration.Metadata.entityID || response.destination != configuration.ACSURL ||
		response.inResponseTo != pending.RequestID || response.issueInstant.After(now.Add(configuration.ClockSkew)) ||
		response.issueInstant.Before(pending.CreatedAt.Add(-configuration.ClockSkew)) {
		return nil, ErrCallbackRejected
	}
	if !validEncryptionShape(configuration.EncryptionPolicy, response.encrypted) {
		return nil, ErrEncryptionRejected
	}
	if err := kernel.verifyResponseSignature(bounded, configuration, responseDocument, response, now); err != nil {
		return nil, err
	}
	assertionDocument := responseDocument
	assertionRoot := response.assertion
	if response.encrypted {
		decryptionRequest := DecryptionRequest{
			Authority: configuration.Authority,
			Response:  append([]byte(nil), responseDocument...), ResponseID: response.id,
			EncryptedObjectID: response.encryptedID, Provider: configuration.Provider,
			BindingID: configuration.BindingID, PlatformLoginRevision: configuration.PlatformLoginRevision,
			AllowedKeyVersions:         append([]uint32(nil), configuration.DecryptionKeyVersions...),
			DirectPlatformKeyRevisions: append([]uint64(nil), configuration.DirectPlatformDecryptionKeyRevisions...),
		}
		decrypted, decryptErr := kernel.assertionDecrypter.DecryptAssertion(bounded, decryptionRequest)
		clear(decryptionRequest.Response)
		if decryptErr != nil || !validDecryptionResult(
			decrypted, response, configuration,
		) ||
			len(decrypted.Assertion) > kernel.limits.MaxDecryptedAssertionBytes {
			clear(decrypted.Assertion)
			return nil, ErrEncryptionRejected
		}
		assertionDocument = append([]byte(nil), decrypted.Assertion...)
		clear(decrypted.Assertion)
		defer clear(assertionDocument)
		assertionRoot, err = parseBoundedXML(assertionDocument, kernel.limits.MaxDecryptedAssertionBytes, kernel.limits)
		if err != nil {
			return nil, ErrEncryptionRejected
		}
	}
	assertion, err := parseAssertion(assertionRoot, configuration, pending, now, kernel.limits)
	if err != nil || assertion.id == response.id {
		return nil, ErrAssertionRejected
	}
	if err := kernel.verifyAssertionSignature(bounded, configuration, responseDocument, response, assertionDocument, assertion, now); err != nil {
		return nil, err
	}
	authentication, err := buildJITAuthentication(assertion, configuration, now, kernel.limits)
	if err != nil {
		return nil, ErrAttributeMappingRejected
	}
	consumption := ConsumptionRequest{
		TransactionID: pending.ID, MaterialID: pending.MaterialID,
		ExpectedVersion: pending.Version, Pins: pending.Pins,
		ResponseID: response.id, AssertionID: assertion.id, ConsumedAt: now,
		ReturnPath: pending.ReturnPath, Authentication: authentication,
	}
	if assertion.sessionIndex != "" {
		consumption.SessionIndexDigest = sessionReplayDigest(configuration.Metadata.entityID, assertion.sessionIndex)
		consumption.HasSessionIndex = true
	}
	result := &ValidatedAuthentication{consumption: consumption}
	result.stage.Store(validatedReady)
	return result, nil
}

func parsePOSTForm(mediaType string, raw []byte, limits Limits) ([]byte, string, error) {
	typeValue, parameters, err := mime.ParseMediaType(mediaType)
	if err != nil || strings.ToLower(typeValue) != "application/x-www-form-urlencoded" || len(parameters) > 1 {
		return nil, "", errors.New("POST form rejected")
	}
	if charset, present := parameters["charset"]; present && !strings.EqualFold(charset, "utf-8") {
		return nil, "", errors.New("POST form rejected")
	} else if len(parameters) == 1 && !present {
		return nil, "", errors.New("POST form rejected")
	}
	maximum, err := MaximumPOSTFormBytes(limits)
	if err != nil || len(raw) == 0 || len(raw) > maximum || strings.ContainsRune(string(raw), ';') || !validXMLText(string(raw)) {
		return nil, "", errors.New("POST form rejected")
	}
	values := make(map[string]string, 2)
	for _, pair := range strings.Split(string(raw), "&") {
		if pair == "" {
			return nil, "", errors.New("POST form rejected")
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, "", errors.New("POST form rejected")
		}
		if parts[0] != "SAMLResponse" && parts[0] != "RelayState" {
			return nil, "", errors.New("POST form rejected")
		}
		key, keyErr := url.QueryUnescape(parts[0])
		value, valueErr := url.QueryUnescape(parts[1])
		if keyErr != nil || valueErr != nil || key != "SAMLResponse" && key != "RelayState" {
			return nil, "", errors.New("POST form rejected")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, "", errors.New("POST form rejected")
		}
		values[key] = value
	}
	if len(values) != 2 || len(values["SAMLResponse"]) > limits.MaxEncodedResponseBytes ||
		len(values["RelayState"]) > maximumRelayStateBytes || !validRelayState(values["RelayState"]) {
		return nil, "", errors.New("POST form rejected")
	}
	document, err := decodeCanonicalBase64(values["SAMLResponse"], limits.MaxEncodedResponseBytes)
	if err != nil || len(document) > limits.MaxDecodedResponseBytes {
		return nil, "", errors.New("POST form rejected")
	}
	return document, values["RelayState"], nil
}

func validRelayState(value string) bool {
	if len(value) != canonicalRelayStateBytes || len(value) > maximumRelayStateBytes {
		return false
	}
	decoded, err := decodeRawURL(value)
	defer clear(decoded)
	return err == nil && validOpaque(decoded)
}

// MaximumPOSTFormBytes returns the largest raw application/x-www-form-urlencoded
// callback body accepted for these semantic limits. Field names and separators
// must remain literal, while every byte in both values may be represented by a
// three-byte percent escape. The decoded base64 and XML ceilings are unchanged.
func MaximumPOSTFormBytes(limits Limits) (int, error) {
	if !validLimits(limits) {
		return 0, ErrInvalidOptions
	}
	const fixedBytes = len("SAMLResponse=") + len("&RelayState=")
	maximum := fixedBytes
	maximumInt := int(^uint(0) >> 1)
	for _, valueBytes := range [...]int{limits.MaxEncodedResponseBytes, canonicalRelayStateBytes} {
		if valueBytes > (maximumInt-maximum)/3 {
			return 0, ErrInvalidOptions
		}
		maximum += 3 * valueBytes
	}
	return maximum, nil
}

func decodeRawURL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("opaque value rejected")
	}
	return decoded, nil
}

func validPendingTransaction(
	pending PendingTransaction,
	observedAt time.Time,
	relayDigest [sha256.Size]byte,
	browserDigest [sha256.Size]byte,
	pins TransactionPins,
) bool {
	return !allZero(pending.ID[:]) && validXMLID(pending.RequestID) && pending.State == TransactionPending &&
		validPersistentSuccessorRevision(pending.Version) && validInstant(pending.CreatedAt) && validInstant(pending.ExpiresAt) &&
		pending.ExpiresAt.Sub(pending.CreatedAt) >= time.Minute &&
		pending.ExpiresAt.Sub(pending.CreatedAt) <= 15*time.Minute && observedAt.Before(pending.ExpiresAt) &&
		!pending.CreatedAt.After(observedAt) && validReturnPath(pending.ReturnPath) &&
		compareDigest(pending.RelayStateDigest, relayDigest) && compareDigest(pending.BrowserDigest, browserDigest) &&
		samePins(pending.Pins, pins)
}

func parseResponse(root *xmlNode) (parsedResponse, error) {
	if root == nil || root.name != (expandedName{space: samlProtocolNamespace, local: "Response"}) ||
		!allowedAttributes(root, expandedName{local: "ID"}, expandedName{local: "Version"},
			expandedName{local: "IssueInstant"}, expandedName{local: "Destination"}, expandedName{local: "InResponseTo"}) ||
		strings.TrimSpace(root.text) != "" || len(root.children) < 3 || len(root.children) > 5 {
		return parsedResponse{}, errors.New("response rejected")
	}
	id, _, err := attribute(root, "", "ID", true, maximumIdentifierBytes)
	version, _, versionErr := attribute(root, "", "Version", true, 16)
	issueRaw, _, issueErr := attribute(root, "", "IssueInstant", true, 64)
	destination, _, destinationErr := attribute(root, "", "Destination", true, maximumEndpointBytes)
	inResponseTo, _, responseErr := attribute(root, "", "InResponseTo", true, maximumIdentifierBytes)
	issueInstant, instantErr := parseSAMLInstant(issueRaw)
	if err != nil || versionErr != nil || issueErr != nil || destinationErr != nil || responseErr != nil || instantErr != nil ||
		version != samlVersion || !validXMLID(id) || !validXMLID(inResponseTo) {
		return parsedResponse{}, errors.New("response rejected")
	}
	index := 0
	issuerNode := root.children[index]
	if issuerNode.name != (expandedName{space: samlAssertionNamespace, local: "Issuer"}) {
		return parsedResponse{}, errors.New("response rejected")
	}
	issuer, err := simpleElementText(issuerNode, maximumEntityIDBytes)
	if err != nil {
		return parsedResponse{}, errors.New("response rejected")
	}
	index++
	hasSignature := false
	if index < len(root.children) && root.children[index].name == (expandedName{space: xmlSignatureNamespace, local: "Signature"}) {
		hasSignature = true
		index++
	}
	if index >= len(root.children) || !validSuccessStatus(root.children[index]) {
		return parsedResponse{}, errors.New("response rejected")
	}
	index++
	if index != len(root.children)-1 {
		return parsedResponse{}, errors.New("response rejected")
	}
	assertionNode := root.children[index]
	response := parsedResponse{id: id, issuer: issuer, destination: destination, inResponseTo: inResponseTo, issueInstant: issueInstant, hasSignature: hasSignature}
	switch assertionNode.name {
	case expandedName{space: samlAssertionNamespace, local: "Assertion"}:
		response.assertion = assertionNode
	case expandedName{space: samlAssertionNamespace, local: "EncryptedAssertion"}:
		response.encrypted = true
		envelope, encryptedErr := validateEncryptedAssertionEnvelope(assertionNode)
		if encryptedErr != nil {
			return parsedResponse{}, errors.New("response rejected")
		}
		response.encryptedID = envelope.id
		response.contentAlgorithm = envelope.contentAlgorithm
		response.keyAlgorithm = envelope.keyAlgorithm
		response.keyDigest = envelope.keyDigest
		response.keyMGF = envelope.keyMGF
	default:
		return parsedResponse{}, errors.New("response rejected")
	}
	return response, nil
}

func validSuccessStatus(node *xmlNode) bool {
	if node == nil || node.name != (expandedName{space: samlProtocolNamespace, local: "Status"}) ||
		!allowedAttributes(node) || len(node.children) != 1 || strings.TrimSpace(node.text) != "" {
		return false
	}
	statusCode := node.children[0]
	if statusCode.name != (expandedName{space: samlProtocolNamespace, local: "StatusCode"}) ||
		!allowedAttributes(statusCode, expandedName{local: "Value"}) || len(statusCode.children) != 0 ||
		strings.TrimSpace(statusCode.text) != "" {
		return false
	}
	value, _, err := attribute(statusCode, "", "Value", true, 512)
	return err == nil && value == samlSuccessStatus
}

type encryptedEnvelope struct {
	id               string
	contentAlgorithm string
	keyAlgorithm     string
	keyDigest        string
	keyMGF           string
}

func validateEncryptedAssertionEnvelope(node *xmlNode) (encryptedEnvelope, error) {
	if node == nil || !allowedAttributes(node) || len(node.children) != 1 || strings.TrimSpace(node.text) != "" {
		return encryptedEnvelope{}, errors.New("encrypted assertion rejected")
	}
	encryptedData := node.children[0]
	if encryptedData.name != (expandedName{space: xmlEncryptionNamespace, local: "EncryptedData"}) ||
		!allowedAttributes(encryptedData, expandedName{local: "Id"}, expandedName{local: "Type"}) ||
		len(encryptedData.children) != 3 || strings.TrimSpace(encryptedData.text) != "" {
		return encryptedEnvelope{}, errors.New("encrypted assertion rejected")
	}
	id, _, err := attribute(encryptedData, "", "Id", true, maximumIdentifierBytes)
	typeValue, _, typeErr := attribute(encryptedData, "", "Type", true, 256)
	if err != nil || typeErr != nil || !validXMLID(id) || typeValue != xmlEncryptionNamespace+"Element" ||
		countNamed(node, expandedName{space: xmlEncryptionNamespace, local: "EncryptedData"}) != 1 ||
		countNamed(node, expandedName{space: xmlEncryptionNamespace, local: "EncryptedKey"}) != 1 ||
		countNamed(node, expandedName{space: xmlEncryptionNamespace, local: "CipherValue"}) != 2 ||
		countNamed(node, expandedName{space: xmlEncryptionNamespace, local: "CipherReference"}) != 0 {
		return encryptedEnvelope{}, errors.New("encrypted assertion rejected")
	}
	contentAlgorithm, methodErr := parseEncryptionMethod(encryptedData.children[0], false)
	keyInfo := encryptedData.children[1]
	if methodErr != nil || keyInfo.name != (expandedName{space: xmlSignatureNamespace, local: "KeyInfo"}) ||
		!allowedAttributes(keyInfo, expandedName{local: "ID"}) || len(keyInfo.children) != 1 ||
		strings.TrimSpace(keyInfo.text) != "" || keyInfo.children[0].name !=
		(expandedName{space: xmlEncryptionNamespace, local: "EncryptedKey"}) {
		return encryptedEnvelope{}, errors.New("encrypted assertion rejected")
	}
	encryptedKey := keyInfo.children[0]
	if !allowedAttributes(encryptedKey, expandedName{local: "Id"}) || len(encryptedKey.children) != 2 ||
		strings.TrimSpace(encryptedKey.text) != "" {
		return encryptedEnvelope{}, errors.New("encrypted assertion rejected")
	}
	keyAlgorithm, digest, mgf, methodErr := parseKeyEncryptionMethod(encryptedKey.children[0])
	if methodErr != nil || !validCipherData(encryptedKey.children[1]) || !validCipherData(encryptedData.children[2]) {
		return encryptedEnvelope{}, errors.New("encrypted assertion rejected")
	}
	if !validContentEncryption(contentAlgorithm) || keyAlgorithm != rsaOAEP11 ||
		!validDigestAlgorithm(digest) || !validMGF(mgf, digest) {
		return encryptedEnvelope{}, errors.New("encrypted assertion rejected")
	}
	return encryptedEnvelope{id: id, contentAlgorithm: contentAlgorithm, keyAlgorithm: keyAlgorithm, keyDigest: digest, keyMGF: mgf}, nil
}

func parseEncryptionMethod(node *xmlNode, key bool) (string, error) {
	if node == nil || node.name != (expandedName{space: xmlEncryptionNamespace, local: "EncryptionMethod"}) ||
		!allowedAttributes(node, expandedName{local: "Algorithm"}) || strings.TrimSpace(node.text) != "" ||
		(key && len(node.children) != 2 || !key && len(node.children) != 0) {
		return "", errors.New("encryption method rejected")
	}
	algorithm, _, err := attribute(node, "", "Algorithm", true, 512)
	return algorithm, err
}

func parseKeyEncryptionMethod(node *xmlNode) (string, string, string, error) {
	algorithm, err := parseEncryptionMethod(node, true)
	if err != nil || node.children[0].name != (expandedName{space: xmlSignatureNamespace, local: "DigestMethod"}) ||
		node.children[1].name != (expandedName{space: xmlEncryption11NS, local: "MGF"}) {
		return "", "", "", errors.New("key encryption method rejected")
	}
	digest, err := algorithmOnlyElement(node.children[0])
	if err != nil {
		return "", "", "", errors.New("key encryption method rejected")
	}
	mgf, err := algorithmOnlyElement(node.children[1])
	if err != nil {
		return "", "", "", errors.New("key encryption method rejected")
	}
	return algorithm, digest, mgf, nil
}

func algorithmOnlyElement(node *xmlNode) (string, error) {
	if !allowedAttributes(node, expandedName{local: "Algorithm"}) || len(node.children) != 0 || strings.TrimSpace(node.text) != "" {
		return "", errors.New("algorithm element rejected")
	}
	value, _, err := attribute(node, "", "Algorithm", true, 512)
	return value, err
}

func validCipherData(node *xmlNode) bool {
	if node == nil || node.name != (expandedName{space: xmlEncryptionNamespace, local: "CipherData"}) ||
		!allowedAttributes(node) || len(node.children) != 1 || strings.TrimSpace(node.text) != "" ||
		node.children[0].name != (expandedName{space: xmlEncryptionNamespace, local: "CipherValue"}) {
		return false
	}
	value, err := simpleElementText(node.children[0], DefaultLimits().MaxEncodedResponseBytes)
	if err != nil {
		return false
	}
	decoded, err := decodeCanonicalBase64(value, DefaultLimits().MaxEncodedResponseBytes)
	clear(decoded)
	return err == nil
}

func countNamed(node *xmlNode, name expandedName) int {
	if node == nil {
		return 0
	}
	count := 0
	if node.name == name {
		count++
	}
	for _, child := range node.children {
		count += countNamed(child, name)
	}
	return count
}

func validDecryptionResult(result DecryptionResult, response parsedResponse, configuration Configuration) bool {
	validRevision := result.DirectPlatformKeyRevision == 0 &&
		slices.Contains(configuration.DecryptionKeyVersions, result.KeyVersion)
	if configuration.Authority == DirectPlatformCeremonyAuthority {
		validRevision = result.KeyVersion == 0 &&
			slices.Contains(configuration.DirectPlatformDecryptionKeyRevisions, result.DirectPlatformKeyRevision)
	}
	return len(result.Assertion) > 0 && result.EncryptedObjectID == response.encryptedID && validRevision &&
		validDecryptionResultAuthority(result, configuration) && validContentEncryption(result.ContentEncryptionAlgorithm) &&
		result.ContentEncryptionAlgorithm == response.contentAlgorithm && result.KeyTransportAlgorithm == rsaOAEP11 &&
		result.KeyTransportAlgorithm == response.keyAlgorithm && validDigestAlgorithm(result.KeyDigestAlgorithm) &&
		result.KeyDigestAlgorithm == response.keyDigest && validMGF(result.MaskGenerationAlgorithm, result.KeyDigestAlgorithm) &&
		result.MaskGenerationAlgorithm == response.keyMGF && result.ExternalDereferenceCount == 0
}

func validDecryptionResultAuthority(result DecryptionResult, configuration Configuration) bool {
	if configuration.Authority == TenantCeremonyAuthority {
		return true
	}
	return configuration.Authority == DirectPlatformCeremonyAuthority &&
		result.Authority == configuration.Authority && result.Provider == configuration.Provider &&
		result.BindingID == configuration.BindingID &&
		result.PlatformLoginRevision == configuration.PlatformLoginRevision
}

func validContentEncryption(value string) bool {
	// crewjam/saml v0.5.1 proves AES-128-GCM interoperability. ADR-0010
	// requires rejecting unproved profiles rather than patching XML Encryption
	// with custom cryptography.
	return value == aes128GCM
}

func validDigestAlgorithm(value string) bool {
	return value == digestSHA256 || value == digestSHA384 || value == digestSHA512
}

func validMGF(value, digest string) bool {
	return digest == digestSHA256 && value == mgf1SHA256 ||
		digest == digestSHA384 && value == mgf1SHA384 || digest == digestSHA512 && value == mgf1SHA512
}

func (kernel *Kernel) Consume(ctx context.Context, authentication *ValidatedAuthentication, consumer AuthenticationConsumer) (ConsumptionResult, error) {
	if kernel == nil || authentication == nil || consumer == nil ||
		!validTransactionPins(authentication.consumption.Pins) ||
		authentication.consumption.Pins.Authority != kernel.authority ||
		!authentication.stage.CompareAndSwap(validatedReady, validatedConsuming) {
		return ConsumptionResult{}, ErrConsumptionRejected
	}
	bounded, cancel, err := operationContext(ctx, kernel.operationTimeout)
	if err != nil {
		authentication.stage.Store(validatedFailed)
		return ConsumptionResult{}, errors.Join(ErrConsumptionRejected, err)
	}
	defer cancel()
	request := authentication.consumption
	request.Authentication = cloneJITAuthentication(request.Authentication)
	result, err := consumer.ConsumeSAML(bounded, request)
	if err != nil || result.Category != ConsumerSuccess {
		authentication.stage.Store(validatedFailed)
		return result, ErrConsumptionRejected
	}
	authentication.stage.Store(validatedConsumed)
	return result, nil
}

func sessionReplayDigest(issuer, sessionIndex string) [sha256.Size]byte {
	return digestFields([]byte(issuer), []byte(sessionIndex))
}
