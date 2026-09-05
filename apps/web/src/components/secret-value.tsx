import { Button } from "@periapsis/ui/components/ui/button";
import { Check, Copy } from "lucide-react";
import { useState } from "react";

interface SecretValueProps {
  label: string;
  value: string;
}

export function SecretValue({
  label,
  value,
}: SecretValueProps): React.JSX.Element {
  const [copyState, setCopyState] = useState<"copied" | "failed" | "idle">(
    "idle",
  );

  async function copyValue(): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <div className="secret-value">
      <div>
        <span>{label}</span>
        <code>{value}</code>
      </div>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => void copyValue()}
        aria-label={`Copy ${label.toLowerCase()}`}
      >
        {copyState === "copied" ? (
          <Check aria-hidden="true" />
        ) : (
          <Copy aria-hidden="true" />
        )}
        {copyState === "copied" ? "Copied" : "Copy"}
      </Button>
      <span className="sr-only" aria-live="polite">
        {copyState === "copied"
          ? `${label} copied to the clipboard.`
          : copyState === "failed"
            ? `Clipboard access failed. Select and copy the ${label.toLowerCase()} manually.`
            : ""}
      </span>
    </div>
  );
}
