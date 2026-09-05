import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import {
  Building2,
  CircleUserRound,
  Clock3,
  KeyRound,
  Laptop,
  Mail,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router";

import { useSession } from "../auth/session-context";
import { mfaSecurityRouteDescriptor } from "../auth/mfa/model";
import { TenantInstant } from "../lib/tenant-date-time-context";

export function UserProfilePage(): React.JSX.Element {
  const { session } = useSession();
  const email = session.user.email?.trim();

  return (
    <div className="content">
      <section className="page-heading" aria-labelledby="user-profile-title">
        <div>
          <p className="section-label">Personal access</p>
          <h1 id="user-profile-title">User profile</h1>
          <p>
            Review the identity and access context returned by the server. Your
            authentication provider remains the source of truth for identity
            attributes.
          </p>
        </div>
        <Badge variant="outline">
          <ShieldCheck aria-hidden="true" /> Server verified
        </Badge>
      </section>

      <section className="session-facts" aria-label="Profile summary">
        <ProfileCard
          description="Display name"
          icon={<CircleUserRound aria-hidden="true" />}
          title={session.user.displayName}
        >
          <dl className="session-metadata">
            <div>
              <dt>
                <Mail aria-hidden="true" /> Email
              </dt>
              <dd>{email || "Not supplied by the identity provider"}</dd>
            </div>
            <div>
              <dt>Identity ID</dt>
              <dd>{session.user.id}</dd>
            </div>
          </dl>
        </ProfileCard>

        <ProfileCard
          description="Current authorization boundary"
          icon={<Building2 aria-hidden="true" />}
          title={session.activeTenantId ? "Tenant context" : "Platform context"}
        >
          <p>
            {session.activeTenantId
              ? "A tenant is selected. Every tenant request is still re-authorized by the API and protected by row-level security."
              : "No tenant is selected. Tenant-scoped operations remain unavailable until you choose an authorized tenant."}
          </p>
          <Badge variant="secondary">
            {session.permissions.length} platform permission
            {session.permissions.length === 1 ? "" : "s"}
          </Badge>
        </ProfileCard>

        <ProfileCard
          description="Current browser session"
          icon={<Clock3 aria-hidden="true" />}
          title="Session lifetime"
        >
          <dl className="session-metadata">
            <div>
              <dt>Idle expiry</dt>
              <dd>
                <ProfileTime value={session.idleExpiresAt} />
              </dd>
            </div>
            <div>
              <dt>Absolute expiry</dt>
              <dd>
                <ProfileTime value={session.absoluteExpiresAt} />
              </dd>
            </div>
          </dl>
        </ProfileCard>
      </section>

      <section
        className="boundary-note"
        aria-labelledby="profile-security-title"
      >
        <div>
          <p className="section-label">Security controls</p>
          <h2 id="profile-security-title">Keep your access current.</h2>
        </div>
        <div>
          <p>
            Inspect and revoke browser sessions. When a tenant is active, you
            can also manage the MFA devices allowed by live policy.
          </p>
          <div className="intro__actions">
            <Button asChild variant="outline">
              <Link to="/sessions">
                <Laptop aria-hidden="true" /> Manage sessions
              </Link>
            </Button>
            {session.activeTenantId ? (
              <Button asChild variant="outline">
                <Link to={mfaSecurityRouteDescriptor.path}>
                  <KeyRound aria-hidden="true" /> Manage MFA devices
                </Link>
              </Button>
            ) : null}
          </div>
        </div>
      </section>
    </div>
  );
}

function ProfileCard({
  children,
  description,
  icon,
  title,
}: {
  children: React.ReactNode;
  description: string;
  icon: React.ReactNode;
  title: string;
}): React.JSX.Element {
  return (
    <Card className="access-fact">
      <CardHeader>
        <span className="access-fact__icon">{icon}</span>
        <div>
          <CardDescription>{description}</CardDescription>
          <CardTitle>{title}</CardTitle>
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function ProfileTime({ value }: { value: string }): React.JSX.Element {
  return <TenantInstant value={value} invalidLabel="Unavailable" />;
}
