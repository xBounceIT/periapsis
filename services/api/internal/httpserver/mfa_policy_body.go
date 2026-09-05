package httpserver

import (
	"errors"
	"net/http"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func decodePlatformMFAPolicyCreateBody(r *http.Request, destination *contract.PlatformMfaPolicyCreateRequest) error {
	return decodeMFAPolicyPublishBody(r, destination, true)
}

func decodeTenantMFAPolicyCreateBody(r *http.Request, destination *contract.TenantMfaPolicyCreateRequest) error {
	return decodeMFAPolicyPublishBody(r, destination, false)
}

func decodePlatformMFAPolicyReplaceBody(r *http.Request, destination *contract.PlatformMfaPolicyReplaceRequest) error {
	return decodeMFAPolicyPublishBody(r, destination, true)
}

func decodeTenantMFAPolicyReplaceBody(r *http.Request, destination *contract.TenantMfaPolicyReplaceRequest) error {
	return decodeMFAPolicyPublishBody(r, destination, false)
}

func decodeMFAPolicyPublishBody(r *http.Request, destination any, platform bool) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"target", "expectedRevision", "requirement"},
		[]string{"target", "expectedRevision", "requirement"},
	)
	if err != nil {
		return err
	}
	if err = validateMFAPolicyTargetJSON(object["target"], platform); err != nil {
		return err
	}
	return validateMFAPolicyRequirementJSON(object["requirement"])
}

func decodePlatformMFAPolicyRetireBody(r *http.Request, destination *contract.PlatformMfaPolicyRetireRequest) error {
	return decodeMFAPolicyRetireBody(r, destination, true)
}

func decodeTenantMFAPolicyRetireBody(r *http.Request, destination *contract.TenantMfaPolicyRetireRequest) error {
	return decodeMFAPolicyRetireBody(r, destination, false)
}

func decodeMFAPolicyRetireBody(r *http.Request, destination any, platform bool) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	object, err := exactTenantLDAPJSONObject(
		raw, []string{"target", "expectedRevision"}, []string{"target", "expectedRevision"},
	)
	if err != nil {
		return err
	}
	return validateMFAPolicyTargetJSON(object["target"], platform)
}

func decodePlatformMFAPolicySimulationBody(
	r *http.Request,
	destination *contract.PlatformMfaPolicySimulationRequest,
) error {
	return decodeMFAPolicySimulationBody(r, destination, true)
}

func decodeTenantMFAPolicySimulationBody(
	r *http.Request,
	destination *contract.TenantMfaPolicySimulationRequest,
) error {
	return decodeMFAPolicySimulationBody(r, destination, false)
}

func decodeMFAPolicySimulationBody(r *http.Request, destination any, platform bool) error {
	raw, err := decodePlatformIdentityProviderJSONBody(r, destination)
	if err != nil {
		return err
	}
	allowed := []string{"operation", "target", "expectedRevision", "expectedPolicyId", "requirement"}
	required := []string{"operation", "target", "expectedRevision"}
	if !platform {
		allowed = append(allowed, "context")
		required = append(required, "context")
	}
	object, err := exactTenantLDAPJSONObject(raw, allowed, required)
	if err != nil {
		return err
	}
	if err = validateMFAPolicyTargetJSON(object["target"], platform); err != nil {
		return err
	}
	if value, present := object["expectedPolicyId"]; present {
		if _, ok := value.(string); !ok {
			return errors.New("MFA policy expectedPolicyId must be a UUID string")
		}
	}
	if value, present := object["requirement"]; present {
		if err = validateMFAPolicyRequirementJSON(value); err != nil {
			return err
		}
	}
	if !platform {
		return validateMFAPolicyContextJSON(object["context"])
	}
	return nil
}

func validateMFAPolicyTargetJSON(raw any, platform bool) error {
	if platform {
		object, err := exactTenantLDAPJSONObject(raw, []string{"scope"}, []string{"scope"})
		if err != nil {
			return err
		}
		if object["scope"] != "platform_floor" {
			return errors.New("platform MFA policy target is invalid")
		}
		return nil
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"scope", "roleId", "securityGroupId", "action"},
		[]string{"scope"},
	)
	if err != nil {
		return err
	}
	scope, ok := object["scope"].(string)
	if !ok {
		return errors.New("tenant MFA policy scope is invalid")
	}
	allowed := []string{"scope"}
	switch scope {
	case "tenant_baseline":
	case "security_group":
		allowed = append(allowed, "securityGroupId")
	case "role":
		allowed = append(allowed, "roleId")
	case "action":
		allowed = append(allowed, "action")
	default:
		return errors.New("tenant MFA policy scope is invalid")
	}
	object, err = exactTenantLDAPJSONObject(raw, allowed, allowed)
	if err != nil {
		return err
	}
	for _, field := range allowed[1:] {
		if _, ok = object[field].(string); !ok {
			return errors.New("tenant MFA policy target discriminator is invalid")
		}
	}
	return nil
}

func validateMFAPolicyRequirementJSON(raw any) error {
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"level", "localRequired", "freshnessSeconds", "enrollmentDeadline"},
		[]string{"level", "localRequired", "freshnessSeconds", "enrollmentDeadline"},
	)
	if err != nil {
		return err
	}
	if object["enrollmentDeadline"] != nil {
		if _, ok := object["enrollmentDeadline"].(string); !ok {
			return errors.New("MFA policy enrollmentDeadline is invalid")
		}
	}
	return nil
}

func validateMFAPolicyContextJSON(raw any) error {
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"roleIds", "securityGroupIds", "action"},
		[]string{"roleIds", "securityGroupIds", "action"},
	)
	if err != nil {
		return err
	}
	if _, ok := object["roleIds"].([]any); !ok {
		return errors.New("MFA policy context roleIds must be an array")
	}
	if _, ok := object["securityGroupIds"].([]any); !ok {
		return errors.New("MFA policy context securityGroupIds must be an array")
	}
	if _, ok := object["action"].(string); !ok {
		return errors.New("MFA policy context action is invalid")
	}
	return nil
}
