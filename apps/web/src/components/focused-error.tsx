import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { TriangleAlert } from "lucide-react";
import { useLayoutEffect, useRef } from "react";

interface FocusedErrorProps {
  autoFocus?: boolean;
  message: string;
  title?: string;
}

export function FocusedError({
  autoFocus = true,
  message,
  title = "This action could not be completed",
}: FocusedErrorProps): React.JSX.Element {
  const alertRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (autoFocus) {
      alertRef.current?.focus();
    }
  }, [autoFocus, message]);

  return (
    <Alert
      ref={alertRef}
      variant="destructive"
      tabIndex={-1}
      className="form-alert"
    >
      <TriangleAlert aria-hidden="true" />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  );
}
