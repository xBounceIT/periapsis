import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { KeyRound, ShieldCheck } from "lucide-react";
import { useId, useState } from "react";

import { FormField } from "../components/form-field";

const providerKeyPattern = /^[a-z][a-z0-9_-]{2,63}$/u;
const unavailableLocator = "_";

interface PlatformOIDCLoginFormProps {
  disabled?: boolean;
}

/**
 * Direct platform SSO is intentionally separate from tenant-bound SSO. The
 * public provider key is used only in the selected OIDC or SAML path, while
 * the strict request body contains the canonical local return path and no
 * identity material.
 */
export function PlatformOIDCLoginForm({
  disabled = false,
}: PlatformOIDCLoginFormProps): React.JSX.Element {
  const [providerKey, setProviderKey] = useState("");
  const id = useId();
  const providerReady = providerKeyPattern.test(providerKey);
  const encodedProvider = providerReady
    ? encodeURIComponent(providerKey)
    : unavailableLocator;
  const oidcAction = `/api/v1/auth/platform/oidc/${encodedProvider}/start`;
  const samlAction = `/api/v1/auth/platform/saml/${encodedProvider}/start`;

  return (
    <form
      className="access-form"
      method="post"
      action={oidcAction}
      encType="application/x-www-form-urlencoded"
    >
      <FormField
        htmlFor={`${id}-platform-provider`}
        label="Platform provider key"
        hint="Use the global workforce provider key supplied by a platform administrator."
      >
        <Input
          id={`${id}-platform-provider`}
          type="text"
          autoComplete="off"
          pattern="[a-z][a-z0-9_-]{2,63}"
          minLength={3}
          maxLength={64}
          required
          value={providerKey}
          onChange={(event) => setProviderKey(event.currentTarget.value)}
          disabled={disabled}
          aria-describedby={`${id}-platform-provider-hint`}
        />
      </FormField>
      <input type="hidden" name="returnPath" value="/" />
      <div className="form-actions">
        <Button
          type="submit"
          size="lg"
          disabled={disabled || !providerReady}
          formAction={oidcAction}
        >
          <ShieldCheck aria-hidden="true" />
          Continue with platform OIDC
        </Button>
        <Button
          type="submit"
          size="lg"
          variant="outline"
          disabled={disabled || !providerReady}
          formAction={samlAction}
        >
          <KeyRound aria-hidden="true" />
          Continue with platform SAML
        </Button>
      </div>
      <p className="form-field__hint">
        These controls only start authentication for the public provider key.
        The server independently decides eligibility and tenant access.
      </p>
    </form>
  );
}
