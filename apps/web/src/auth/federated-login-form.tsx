import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Building2, KeyRound } from "lucide-react";
import { useId, useState } from "react";

import { FormField } from "../components/form-field";

const tenantSlugPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const loginKeyPattern = /^[a-z][a-z0-9_-]{2,63}$/u;
const unavailableLocator = "_";

interface FederatedLoginFormProps {
  disabled?: boolean;
}

/**
 * Federated starts intentionally use a native top-level form submission. A
 * scripted fetch cannot safely turn an opaque cross-origin 303 into browser
 * navigation. Locator inputs have no name, so the strict backend form body
 * contains only the server-validated relative returnPath.
 */
export function FederatedLoginForm({
  disabled = false,
}: FederatedLoginFormProps): React.JSX.Element {
  const [tenantSlug, setTenantSlug] = useState("");
  const [loginKey, setLoginKey] = useState("");
  const id = useId();
  const locatorReady =
    tenantSlugPattern.test(tenantSlug) && loginKeyPattern.test(loginKey);
  const encodedTenant = locatorReady
    ? encodeURIComponent(tenantSlug)
    : unavailableLocator;
  const encodedLoginKey = locatorReady
    ? encodeURIComponent(loginKey)
    : unavailableLocator;
  const oidcAction = `/api/v1/auth/federated/oidc/${encodedTenant}/${encodedLoginKey}/start`;
  const samlAction = `/api/v1/auth/federated/saml/${encodedTenant}/${encodedLoginKey}/start`;

  return (
    <form
      className="access-form"
      method="post"
      action={oidcAction}
      encType="application/x-www-form-urlencoded"
    >
      <FormField
        htmlFor={`${id}-sso-tenant`}
        label="Tenant slug"
        hint="Use the lowercase organization slug supplied by your administrator."
      >
        <Input
          id={`${id}-sso-tenant`}
          type="text"
          autoComplete="organization"
          pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
          minLength={1}
          maxLength={63}
          required
          value={tenantSlug}
          onChange={(event) => setTenantSlug(event.currentTarget.value)}
          disabled={disabled}
          aria-describedby={`${id}-sso-tenant-hint`}
        />
      </FormField>
      <FormField
        htmlFor={`${id}-sso-provider`}
        label="Provider login key"
        hint="This is the public provider alias, not a client secret or issuer URL."
      >
        <Input
          id={`${id}-sso-provider`}
          type="text"
          autoComplete="off"
          pattern="[a-z][a-z0-9_-]{2,63}"
          minLength={3}
          maxLength={64}
          required
          value={loginKey}
          onChange={(event) => setLoginKey(event.currentTarget.value)}
          disabled={disabled}
          aria-describedby={`${id}-sso-provider-hint`}
        />
      </FormField>
      <input type="hidden" name="returnPath" value="/" />
      <div className="form-actions">
        <Button
          type="submit"
          size="lg"
          disabled={disabled || !locatorReady}
          formAction={oidcAction}
        >
          <Building2 aria-hidden="true" />
          Continue with OIDC
        </Button>
        <Button
          type="submit"
          size="lg"
          variant="outline"
          disabled={disabled || !locatorReady}
          formAction={samlAction}
        >
          <KeyRound aria-hidden="true" />
          Continue with SAML
        </Button>
      </div>
      <p className="form-field__hint">
        Your browser leaves this console and returns through a one-time,
        provider-bound callback. Existing sessions cannot be replaced by this
        flow.
      </p>
    </form>
  );
}
