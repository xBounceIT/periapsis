import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { ShieldX } from "lucide-react";

export function ServerDenied({
  resource,
}: {
  resource: string;
}): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section className="page-heading" aria-labelledby="server-denied-title">
        <div>
          <p className="section-label">Live authorization decision</p>
          <h1 id="server-denied-title">Access was denied by the server.</h1>
          <p>
            This direct route requested {resource} in the active tenant. The API
            denied that request, so no resource data is displayed.
          </p>
        </div>
      </section>
      <Alert variant="destructive">
        <ShieldX aria-hidden="true" />
        <AlertTitle>Server permission required</AlertTitle>
        <AlertDescription>
          Navigation visibility is only a convenience. Backend policy remains
          the authority for direct links and every operation.
        </AlertDescription>
      </Alert>
    </div>
  );
}
