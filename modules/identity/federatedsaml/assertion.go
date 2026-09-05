package federatedsaml

import (
	"errors"
	"slices"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type attributeKey struct {
	name   string
	format string
}

type parsedAssertion struct {
	id                     string
	issuer                 string
	issueInstant           time.Time
	hasSignature           bool
	nameID                 string
	nameIDFormat           string
	subjectNotOnOrAfter    time.Time
	conditionsNotBefore    *time.Time
	conditionsNotOnOrAfter time.Time
	authenticatedAt        time.Time
	sessionIndex           string
	sessionNotOnOrAfter    *time.Time
	authnContext           string
	attributes             map[attributeKey][]string
}

func parseAssertion(root *xmlNode, configuration Configuration, pending PendingTransaction, now time.Time, limits Limits) (parsedAssertion, error) {
	if root == nil || root.name != (expandedName{space: samlAssertionNamespace, local: "Assertion"}) ||
		!allowedAttributes(root, expandedName{local: "ID"}, expandedName{local: "Version"}, expandedName{local: "IssueInstant"}) ||
		strings.TrimSpace(root.text) != "" || len(root.children) < 4 || len(root.children) > 6 {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	id, _, idErr := attribute(root, "", "ID", true, maximumIdentifierBytes)
	version, _, versionErr := attribute(root, "", "Version", true, 16)
	issueRaw, _, issueErr := attribute(root, "", "IssueInstant", true, 64)
	issueInstant, instantErr := parseSAMLInstant(issueRaw)
	if idErr != nil || versionErr != nil || issueErr != nil || instantErr != nil || !validXMLID(id) ||
		version != samlVersion || issueInstant.After(now.Add(configuration.ClockSkew)) ||
		issueInstant.Before(pending.CreatedAt.Add(-configuration.ClockSkew)) {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	result := parsedAssertion{id: id, issueInstant: issueInstant, attributes: make(map[attributeKey][]string)}
	index := 0
	if root.children[index].name != (expandedName{space: samlAssertionNamespace, local: "Issuer"}) {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	issuer, err := simpleElementText(root.children[index], maximumEntityIDBytes)
	if err != nil || issuer != configuration.Metadata.entityID {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	result.issuer = issuer
	index++
	if index < len(root.children) && root.children[index].name == (expandedName{space: xmlSignatureNamespace, local: "Signature"}) {
		result.hasSignature = true
		index++
	}
	if index >= len(root.children) || root.children[index].name != (expandedName{space: samlAssertionNamespace, local: "Subject"}) {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	nameID, nameIDFormat, subjectExpiry, err := parseSubject(root.children[index], configuration, pending, now)
	if err != nil {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	result.nameID, result.nameIDFormat = nameID, nameIDFormat
	result.subjectNotOnOrAfter = subjectExpiry
	index++
	if index >= len(root.children) || root.children[index].name != (expandedName{space: samlAssertionNamespace, local: "Conditions"}) {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	result.conditionsNotBefore, result.conditionsNotOnOrAfter, err = parseConditions(root.children[index], configuration, now)
	if err != nil {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	index++
	if index >= len(root.children) || root.children[index].name != (expandedName{space: samlAssertionNamespace, local: "AuthnStatement"}) {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	result.authenticatedAt, result.sessionIndex, result.sessionNotOnOrAfter, result.authnContext, err =
		parseAuthnStatement(root.children[index], configuration, now)
	if err != nil {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	index++
	if index < len(root.children) {
		if index != len(root.children)-1 || root.children[index].name != (expandedName{space: samlAssertionNamespace, local: "AttributeStatement"}) {
			return parsedAssertion{}, errors.New("assertion rejected")
		}
		result.attributes, err = parseAttributeStatement(root.children[index], limits)
		if err != nil {
			return parsedAssertion{}, errors.New("assertion rejected")
		}
		index++
	}
	if index != len(root.children) || countNamed(root, expandedName{space: samlAssertionNamespace, local: "AuthnStatement"}) != 1 ||
		countNamed(root, expandedName{space: samlAssertionNamespace, local: "SubjectConfirmation"}) != 1 {
		return parsedAssertion{}, errors.New("assertion rejected")
	}
	return result, nil
}

func parseSubject(node *xmlNode, configuration Configuration, pending PendingTransaction, now time.Time) (string, string, time.Time, error) {
	if !allowedAttributes(node) || strings.TrimSpace(node.text) != "" || len(node.children) < 1 || len(node.children) > 2 {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	index := 0
	var nameID, nameIDFormat string
	if node.children[index].name == (expandedName{space: samlAssertionNamespace, local: "NameID"}) {
		nameNode := node.children[index]
		if !allowedAttributes(nameNode, expandedName{local: "Format"}) || len(nameNode.children) != 0 {
			return "", "", time.Time{}, errors.New("subject rejected")
		}
		format, _, err := attribute(nameNode, "", "Format", true, maximumAttributeNameBytes)
		if err != nil || format != samlPersistentNameID {
			return "", "", time.Time{}, errors.New("subject rejected")
		}
		value, err := elementText(nameNode, maximumAttributeValueBytes)
		if err != nil {
			return "", "", time.Time{}, errors.New("subject rejected")
		}
		nameID, nameIDFormat = value, format
		index++
	}
	if configuration.Subject.Source == SubjectPersistentNameID && nameID == "" {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	if index != len(node.children)-1 || node.children[index].name != (expandedName{space: samlAssertionNamespace, local: "SubjectConfirmation"}) {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	confirmation := node.children[index]
	if !allowedAttributes(confirmation, expandedName{local: "Method"}) || len(confirmation.children) != 1 ||
		strings.TrimSpace(confirmation.text) != "" {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	method, _, err := attribute(confirmation, "", "Method", true, 512)
	if err != nil || method != samlBearerConfirmation || confirmation.children[0].name !=
		(expandedName{space: samlAssertionNamespace, local: "SubjectConfirmationData"}) {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	data := confirmation.children[0]
	if !allowedAttributes(data, expandedName{local: "Recipient"}, expandedName{local: "InResponseTo"},
		expandedName{local: "NotBefore"}, expandedName{local: "NotOnOrAfter"}) ||
		len(data.children) != 0 || strings.TrimSpace(data.text) != "" {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	recipient, _, recipientErr := attribute(data, "", "Recipient", true, maximumEndpointBytes)
	inResponseTo, _, responseErr := attribute(data, "", "InResponseTo", true, maximumIdentifierBytes)
	notOnOrAfterRaw, _, expiryErr := attribute(data, "", "NotOnOrAfter", true, 64)
	notOnOrAfter, instantErr := parseSAMLInstant(notOnOrAfterRaw)
	if recipientErr != nil || responseErr != nil || expiryErr != nil || instantErr != nil ||
		recipient != configuration.ACSURL || inResponseTo != pending.RequestID {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	var notBefore *time.Time
	if raw, present, valueErr := attribute(data, "", "NotBefore", false, 64); valueErr != nil {
		return "", "", time.Time{}, errors.New("subject rejected")
	} else if present {
		value, parseErr := parseSAMLInstant(raw)
		if parseErr != nil {
			return "", "", time.Time{}, errors.New("subject rejected")
		}
		notBefore = &value
	}
	if !validTimeWindow(now, notBefore, notOnOrAfter, configuration.ClockSkew) {
		return "", "", time.Time{}, errors.New("subject rejected")
	}
	return nameID, nameIDFormat, notOnOrAfter, nil
}

func parseConditions(node *xmlNode, configuration Configuration, now time.Time) (*time.Time, time.Time, error) {
	if !allowedAttributes(node, expandedName{local: "NotBefore"}, expandedName{local: "NotOnOrAfter"}) ||
		len(node.children) == 0 || strings.TrimSpace(node.text) != "" {
		return nil, time.Time{}, errors.New("conditions rejected")
	}
	expiryRaw, _, err := attribute(node, "", "NotOnOrAfter", true, 64)
	expiry, parseErr := parseSAMLInstant(expiryRaw)
	if err != nil || parseErr != nil {
		return nil, time.Time{}, errors.New("conditions rejected")
	}
	var notBefore *time.Time
	if raw, present, valueErr := attribute(node, "", "NotBefore", false, 64); valueErr != nil {
		return nil, time.Time{}, errors.New("conditions rejected")
	} else if present {
		value, valueParseErr := parseSAMLInstant(raw)
		if valueParseErr != nil {
			return nil, time.Time{}, errors.New("conditions rejected")
		}
		notBefore = &value
	}
	if !validTimeWindow(now, notBefore, expiry, configuration.ClockSkew) {
		return nil, time.Time{}, errors.New("conditions rejected")
	}
	for _, restriction := range node.children {
		if restriction.name != (expandedName{space: samlAssertionNamespace, local: "AudienceRestriction"}) ||
			!allowedAttributes(restriction) || len(restriction.children) != 1 || strings.TrimSpace(restriction.text) != "" ||
			restriction.children[0].name != (expandedName{space: samlAssertionNamespace, local: "Audience"}) {
			return nil, time.Time{}, errors.New("conditions rejected")
		}
		audience, textErr := simpleElementText(restriction.children[0], maximumEntityIDBytes)
		if textErr != nil || audience != configuration.SPEntityID {
			return nil, time.Time{}, errors.New("conditions rejected")
		}
	}
	return notBefore, expiry, nil
}

func parseAuthnStatement(node *xmlNode, configuration Configuration, now time.Time) (time.Time, string, *time.Time, string, error) {
	if !allowedAttributes(node, expandedName{local: "AuthnInstant"}, expandedName{local: "SessionIndex"},
		expandedName{local: "SessionNotOnOrAfter"}) || len(node.children) != 1 || strings.TrimSpace(node.text) != "" ||
		node.children[0].name != (expandedName{space: samlAssertionNamespace, local: "AuthnContext"}) {
		return time.Time{}, "", nil, "", errors.New("authn statement rejected")
	}
	authnRaw, _, err := attribute(node, "", "AuthnInstant", true, 64)
	authenticatedAt, parseErr := parseSAMLInstant(authnRaw)
	if err != nil || parseErr != nil || authenticatedAt.After(now.Add(configuration.ClockSkew)) ||
		now.Sub(authenticatedAt) > configuration.MaxAuthenticationAge {
		return time.Time{}, "", nil, "", errors.New("authn statement rejected")
	}
	sessionIndex, sessionPresent, err := attribute(node, "", "SessionIndex", false, maximumSessionIndexBytes)
	if err != nil || sessionPresent && !validBoundedString(sessionIndex, maximumSessionIndexBytes) {
		return time.Time{}, "", nil, "", errors.New("authn statement rejected")
	}
	var sessionExpiry *time.Time
	if raw, present, valueErr := attribute(node, "", "SessionNotOnOrAfter", false, 64); valueErr != nil {
		return time.Time{}, "", nil, "", errors.New("authn statement rejected")
	} else if present {
		value, valueErr := parseSAMLInstant(raw)
		if valueErr != nil || !now.Add(-configuration.ClockSkew).Before(value) {
			return time.Time{}, "", nil, "", errors.New("authn statement rejected")
		}
		sessionExpiry = &value
	}
	contextNode := node.children[0]
	if !allowedAttributes(contextNode) || len(contextNode.children) != 1 || strings.TrimSpace(contextNode.text) != "" ||
		contextNode.children[0].name != (expandedName{space: samlAssertionNamespace, local: "AuthnContextClassRef"}) {
		return time.Time{}, "", nil, "", errors.New("authn statement rejected")
	}
	classRef, err := simpleElementText(contextNode.children[0], maximumAuthnContextBytes)
	if err != nil || !slices.Contains(configuration.RequestedAuthnContexts, classRef) {
		return time.Time{}, "", nil, "", errors.New("authn statement rejected")
	}
	return authenticatedAt, sessionIndex, sessionExpiry, classRef, nil
}

func parseAttributeStatement(node *xmlNode, limits Limits) (map[attributeKey][]string, error) {
	if !allowedAttributes(node) || len(node.children) == 0 || len(node.children) > limits.MaxAttributes || strings.TrimSpace(node.text) != "" {
		return nil, errors.New("attribute statement rejected")
	}
	result := make(map[attributeKey][]string, len(node.children))
	for _, attributeNode := range node.children {
		if attributeNode.name != (expandedName{space: samlAssertionNamespace, local: "Attribute"}) ||
			!allowedAttributes(attributeNode, expandedName{local: "Name"}, expandedName{local: "NameFormat"}) ||
			len(attributeNode.children) == 0 || len(attributeNode.children) > limits.MaxValuesPerAttribute || strings.TrimSpace(attributeNode.text) != "" {
			return nil, errors.New("attribute statement rejected")
		}
		name, _, nameErr := attribute(attributeNode, "", "Name", true, maximumAttributeNameBytes)
		format, _, formatErr := attribute(attributeNode, "", "NameFormat", true, maximumAttributeNameBytes)
		key := attributeKey{name: name, format: format}
		if nameErr != nil || formatErr != nil || !validAttributeIdentity(name, format) {
			return nil, errors.New("attribute statement rejected")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errors.New("attribute statement rejected")
		}
		seenValues := make(map[string]struct{}, len(attributeNode.children))
		values := make([]string, 0, len(attributeNode.children))
		for _, valueNode := range attributeNode.children {
			if valueNode.name != (expandedName{space: samlAssertionNamespace, local: "AttributeValue"}) {
				return nil, errors.New("attribute statement rejected")
			}
			value, valueErr := simpleElementText(valueNode, maximumAttributeValueBytes)
			if valueErr != nil {
				return nil, errors.New("attribute statement rejected")
			}
			if _, duplicate := seenValues[value]; duplicate {
				return nil, errors.New("attribute statement rejected")
			}
			seenValues[value] = struct{}{}
			values = append(values, value)
		}
		result[key] = values
	}
	return result, nil
}

func validTimeWindow(now time.Time, notBefore *time.Time, notOnOrAfter time.Time, skew time.Duration) bool {
	return (notBefore == nil || !now.Add(skew).Before(*notBefore)) && now.Add(-skew).Before(notOnOrAfter) &&
		(notBefore == nil || notBefore.Before(notOnOrAfter))
}

func buildJITAuthentication(assertion parsedAssertion, configuration Configuration, now time.Time, limits Limits) (JITAuthentication, error) {
	result := JITAuthentication{
		issuer: assertion.issuer, subjectSource: configuration.Subject.Source,
		authnContext: assertion.authnContext, authenticatedAt: assertion.authenticatedAt,
		validUntil:       assertion.conditionsNotOnOrAfter,
		protectedSession: SessionMaterial{NameID: assertion.nameID, NameIDFormat: assertion.nameIDFormat, SessionIndex: assertion.sessionIndex},
	}
	if assertion.subjectNotOnOrAfter.Before(result.validUntil) {
		result.validUntil = assertion.subjectNotOnOrAfter
	}
	if assertion.sessionNotOnOrAfter != nil && assertion.sessionNotOnOrAfter.Before(result.validUntil) {
		result.validUntil = *assertion.sessionNotOnOrAfter
	}
	switch configuration.Subject.Source {
	case SubjectPersistentNameID:
		if assertion.nameID == "" || assertion.nameIDFormat != samlPersistentNameID {
			return JITAuthentication{}, errors.New("subject mapping rejected")
		}
		result.subjectName, result.subjectFormat, result.subjectValue = "NameID", assertion.nameIDFormat, assertion.nameID
	case SubjectImmutableAttribute:
		values := assertion.attributes[attributeKey{name: configuration.Subject.AttributeName, format: configuration.Subject.AttributeNameFormat}]
		if len(values) != 1 {
			return JITAuthentication{}, errors.New("subject mapping rejected")
		}
		result.subjectName, result.subjectFormat, result.subjectValue = configuration.Subject.AttributeName,
			configuration.Subject.AttributeNameFormat, values[0]
	default:
		return JITAuthentication{}, errors.New("subject mapping rejected")
	}
	for _, rule := range configuration.Mapping.Scalars {
		values := assertion.attributes[attributeKey{name: rule.Name, format: rule.NameFormat}]
		if len(values) > 1 || rule.Required && len(values) != 1 {
			return JITAuthentication{}, errors.New("scalar mapping rejected")
		}
		if len(values) == 1 {
			result.scalars = append(result.scalars, NamedScalar{Name: rule.Name, Value: values[0]})
		}
	}
	for _, rule := range configuration.Mapping.Profiles {
		values := assertion.attributes[attributeKey{name: rule.Name, format: rule.NameFormat}]
		if len(values) > 1 || rule.Required && len(values) != 1 {
			return JITAuthentication{}, errors.New("profile mapping rejected")
		}
		if len(values) == 1 {
			result.profiles = append(result.profiles, ProfileValue{Field: rule.Field, Value: values[0]})
		}
	}
	if rule := configuration.Mapping.Groups; rule != nil {
		values := assertion.attributes[attributeKey{name: rule.Name, format: rule.NameFormat}]
		if rule.Required && len(values) == 0 || len(values) > limits.MaxGroups {
			return JITAuthentication{}, errors.New("group mapping rejected")
		}
		result.groups = append(result.groups, values...)
		slices.Sort(result.groups)
	}
	for _, rule := range configuration.TrustRules {
		if rule.ClassRef != assertion.authnContext {
			continue
		}
		expires := assertion.authenticatedAt.Add(rule.MaxAge).UTC()
		if result.validUntil.Before(expires) {
			expires = result.validUntil
		}
		if !now.Before(expires) {
			break
		}
		revision := rule.Revision
		result.assurance = &identity.AssuranceEvidence{
			Level: rule.Level, Kind: identity.AssuranceEvidenceFactor,
			Source:          identity.AssuranceSource{ProviderID: configuration.Provider.ProviderID, BindingID: configuration.BindingID},
			AuthenticatedAt: assertion.authenticatedAt.UTC(), ExpiresAt: &expires,
			TrustRuleRevision: &revision,
		}
		break
	}
	return result, nil
}
