package webauthn

import "fmt"

func (b CeremonyBinding) String() string {
	return fmt.Sprintf("webauthn.CeremonyBinding{purpose:%d,evidence:%d,provenance:[REDACTED]}",
		b.Purpose, len(b.BaselineEvidence))
}
func (b CeremonyBinding) GoString() string { return b.String() }

func (c ClaimedCeremony) String() string   { return c.PendingCeremony.String() }
func (c ClaimedCeremony) GoString() string { return c.String() }

func (c CeremonyClaim) String() string   { return "webauthn.CeremonyClaim{proof:[REDACTED]}" }
func (c CeremonyClaim) GoString() string { return c.String() }

func (l CredentialLookup) String() string {
	return "webauthn.CredentialLookup{material:[REDACTED]}"
}
func (l CredentialLookup) GoString() string { return l.String() }

func (c RegistrationCompletion) String() string {
	return "webauthn.RegistrationCompletion{material:[REDACTED]}"
}
func (c RegistrationCompletion) GoString() string { return c.String() }

func (c AuthenticationCompletion) String() string {
	return "webauthn.AuthenticationCompletion{material:[REDACTED]}"
}
func (c AuthenticationCompletion) GoString() string { return c.String() }

func (r RegistrationVerificationRequest) String() string {
	return "webauthn.RegistrationVerificationRequest{material:[REDACTED]}"
}
func (r RegistrationVerificationRequest) GoString() string { return r.String() }

func (p RegistrationProof) String() string {
	return "webauthn.RegistrationProof{material:[REDACTED]}"
}
func (p RegistrationProof) GoString() string { return p.String() }

func (r AuthenticationVerificationRequest) String() string {
	return "webauthn.AuthenticationVerificationRequest{material:[REDACTED]}"
}
func (r AuthenticationVerificationRequest) GoString() string { return r.String() }

func (p AuthenticationProof) String() string {
	return "webauthn.AuthenticationProof{material:[REDACTED]}"
}
func (p AuthenticationProof) GoString() string { return p.String() }

func (r RegistrationStartRequest) String() string {
	return "webauthn.RegistrationStartRequest{material:[REDACTED]}"
}
func (r RegistrationStartRequest) GoString() string { return r.String() }

func (r AuthenticationStartRequest) String() string {
	return "webauthn.AuthenticationStartRequest{material:[REDACTED]}"
}
func (r AuthenticationStartRequest) GoString() string { return r.String() }
