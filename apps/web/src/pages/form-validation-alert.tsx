import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { ShieldAlert } from "lucide-react";

export function FormValidationAlert({
  errors,
  title,
}: {
  errors: readonly string[];
  title: string;
}): React.JSX.Element | null {
  if (errors.length === 0) return null;
  return (
    <Alert variant="destructive">
      <ShieldAlert aria-hidden="true" />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        <ul>
          {errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  );
}
