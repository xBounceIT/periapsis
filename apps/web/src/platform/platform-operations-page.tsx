import { useSession } from "../auth/session-context";
import { describePhaseTwoError } from "../lib/phase-two-types";
import { platformOperationsApi } from "./platform-operations-api";
import { platformOperationsAuthority } from "./platform-operations-authority";
import { PlatformOperationsWorkspace } from "./platform-operations-workspace";

export function PlatformOperationsPage(): React.JSX.Element {
  const { session } = useSession();

  return (
    <div className="content">
      <PlatformOperationsWorkspace
        api={platformOperationsApi}
        authority={platformOperationsAuthority(session)}
        csrfToken={session.csrfToken}
        describeError={describePhaseTwoError}
        sessionKey={session.id}
      />
    </div>
  );
}
