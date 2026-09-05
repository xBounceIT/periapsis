import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Network } from "lucide-react";
import { useId, useState } from "react";

import { FormField } from "../components/form-field";

const providerKeyPattern = /^[a-z][a-z0-9_-]{2,63}$/u;
const unavailableProvider = "_";

export function PlatformLDAPLoginForm({
  disabled = false,
}: {
  disabled?: boolean;
}): React.JSX.Element {
  const [providerKey, setProviderKey] = useState("");
  const id = useId();
  const providerReady = providerKeyPattern.test(providerKey);
  const encodedProvider = providerReady
    ? encodeURIComponent(providerKey)
    : unavailableProvider;

  return (
    <form
      className="access-form"
      method="post"
      action={`/api/v1/auth/platform/ldap/${encodedProvider}`}
      encType="application/x-www-form-urlencoded"
    >
      <FormField
        htmlFor={`${id}-platform-ldap-provider`}
        label="Platform LDAP provider key"
        hint="Public global directory key; no tenant locator is accepted."
      >
        <Input
          id={`${id}-platform-ldap-provider`}
          autoComplete="off"
          disabled={disabled}
          maxLength={64}
          minLength={3}
          pattern="[a-z][a-z0-9_-]{2,63}"
          required
          value={providerKey}
          onChange={(event) => setProviderKey(event.currentTarget.value)}
        />
      </FormField>
      <FormField
        htmlFor={`${id}-platform-ldap-username`}
        label="Platform directory username"
      >
        <Input
          id={`${id}-platform-ldap-username`}
          autoComplete="username"
          disabled={disabled}
          maxLength={320}
          minLength={1}
          name="username"
          required
        />
      </FormField>
      <FormField
        htmlFor={`${id}-platform-ldap-password`}
        label="Platform directory password"
      >
        <Input
          id={`${id}-platform-ldap-password`}
          autoComplete="current-password"
          disabled={disabled}
          maxLength={1024}
          minLength={1}
          name="password"
          required
          type="password"
        />
      </FormField>
      <FormField
        htmlFor={`${id}-platform-ldap-totp`}
        label="Local authenticator code"
        hint="Mandatory local TOTP proof for the existing platform user."
      >
        <Input
          id={`${id}-platform-ldap-totp`}
          autoComplete="one-time-code"
          disabled={disabled}
          inputMode="numeric"
          maxLength={8}
          minLength={6}
          name="totpCode"
          pattern="[0-9]{6,8}"
          required
        />
      </FormField>
      <input name="returnPath" type="hidden" value="/" />
      <Button
        disabled={disabled || !providerReady}
        formAction={`/api/v1/auth/platform/ldap/${encodedProvider}`}
        size="lg"
        type="submit"
        variant="outline"
      >
        <Network aria-hidden="true" /> Continue with platform LDAP
      </Button>
      <p className="form-field__hint">
        The server returns one uniform failure for unknown users, bad directory
        credentials, missing mappings, and invalid TOTP. No user is created.
      </p>
    </form>
  );
}
