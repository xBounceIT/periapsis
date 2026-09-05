import { Label } from "@periapsis/ui/components/ui/label";
import type { ReactNode } from "react";

interface FormFieldProps {
  children: ReactNode;
  error?: string;
  hint?: string;
  htmlFor: string;
  label: string;
  optional?: boolean;
}

export function FormField({
  children,
  error,
  hint,
  htmlFor,
  label,
  optional = false,
}: FormFieldProps): React.JSX.Element {
  return (
    <div className="form-field" data-invalid={error ? "true" : undefined}>
      <div className="form-field__label">
        <Label htmlFor={htmlFor}>{label}</Label>
        {optional ? <span>Optional</span> : null}
      </div>
      {children}
      {hint && !error ? (
        <p id={`${htmlFor}-hint`} className="form-field__hint">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${htmlFor}-error`} className="form-field__error">
          {error}
        </p>
      ) : null}
    </div>
  );
}
