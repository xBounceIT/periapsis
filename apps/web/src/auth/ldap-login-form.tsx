import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Network } from "lucide-react";
import { useId, useState } from "react";

import { FormField } from "../components/form-field";

const tenantSlugPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const loginKeyPattern = /^[a-z][a-z0-9_-]{2,63}$/u;
const unavailableLocator = "_";

interface LDAPLoginFormProps {
  disabled?: boolean;
}

/**
 * LDAP sign-in is deliberately a native form, physically separate from the
 * OIDC/SAML start forms. The password is posted only to the synchronous LDAP
 * endpoint and is never read by application JavaScript or a generated client.
 */
export function LDAPLoginForm({
  disabled = false,
}: LDAPLoginFormProps): React.JSX.Element {
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
  const action = `/api/v1/auth/ldap/${encodedTenant}/${encodedLoginKey}`;

  return (
    <form
      className="access-form"
      method="post"
      action={action}
      encType="application/x-www-form-urlencoded"
    >
      <FormField
        htmlFor={`${id}-ldap-tenant`}
        label="Directory tenant slug"
        hint="Use the lowercase organization slug supplied by your administrator."
      >
        <Input
          id={`${id}-ldap-tenant`}
          type="text"
          autoComplete="organization"
          pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
          minLength={1}
          maxLength={63}
          required
          value={tenantSlug}
          onChange={(event) => setTenantSlug(event.currentTarget.value)}
          disabled={disabled}
          aria-describedby={`${id}-ldap-tenant-hint`}
        />
      </FormField>
      <FormField
        htmlFor={`${id}-ldap-provider`}
        label="Directory login key"
        hint="This is the public directory alias, never a bind DN or secret."
      >
        <Input
          id={`${id}-ldap-provider`}
          type="text"
          autoComplete="off"
          pattern="[a-z][a-z0-9_-]{2,63}"
          minLength={3}
          maxLength={64}
          required
          value={loginKey}
          onChange={(event) => setLoginKey(event.currentTarget.value)}
          disabled={disabled}
          aria-describedby={`${id}-ldap-provider-hint`}
        />
      </FormField>
      <FormField htmlFor={`${id}-ldap-username`} label="Directory username">
        <Input
          id={`${id}-ldap-username`}
          name="username"
          type="text"
          autoComplete="username"
          required
          minLength={1}
          maxLength={320}
          disabled={disabled}
        />
      </FormField>
      <FormField htmlFor={`${id}-ldap-password`} label="Directory password">
        <Input
          id={`${id}-ldap-password`}
          name="password"
          type="password"
          autoComplete="current-password"
          required
          minLength={1}
          maxLength={1024}
          disabled={disabled}
        />
      </FormField>
      <input type="hidden" name="returnPath" value="/" />
      <Button type="submit" size="lg" disabled={disabled || !locatorReady}>
        <Network aria-hidden="true" />
        Continue with directory
      </Button>
      <p className="form-field__hint">
        The directory password is sent only to this tenant-bound LDAP sign-in
        endpoint. It is never sent to an OIDC or SAML provider.
      </p>
    </form>
  );
}
