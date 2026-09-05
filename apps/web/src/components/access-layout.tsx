import { Orbit, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

const accessSteps = [
  { label: "Identity", detail: "Verify the operator" },
  { label: "MFA proof", detail: "Raise assurance" },
  { label: "Session", detail: "Issue a protected cookie" },
  { label: "Tenant", detail: "Use assigned access only" },
] as const;

interface AccessLayoutProps {
  activeStep: number;
  children: ReactNode;
  description: string;
  eyebrow: string;
  title: string;
}

export function AccessLayout({
  activeStep,
  children,
  description,
  eyebrow,
  title,
}: AccessLayoutProps): React.JSX.Element {
  return (
    <div className="access-page">
      <aside className="access-console" aria-label="Authentication progress">
        <a href="/" className="brand access-console__brand">
          <span className="brand__mark" aria-hidden="true">
            <Orbit />
          </span>
          <span>
            <strong>Periapsis</strong>
            <small>Incident operations</small>
          </span>
        </a>

        <div className="access-console__copy">
          <p className="section-label">Emergency control plane</p>
          <p>
            Access crosses one boundary at a time. The API verifies every step;
            this screen never grants authority by itself.
          </p>
        </div>

        <ol className="access-orbit">
          {accessSteps.map((step, index) => {
            const state =
              index < activeStep
                ? "complete"
                : index === activeStep
                  ? "current"
                  : "pending";
            return (
              <li key={step.label} data-state={state}>
                <span className="access-orbit__node" aria-hidden="true">
                  {state === "complete" ? <ShieldCheck /> : index + 1}
                </span>
                <span>
                  <strong>{step.label}</strong>
                  <small>{step.detail}</small>
                </span>
                <span className="sr-only">
                  {state === "complete"
                    ? "Complete"
                    : state === "current"
                      ? "Current step"
                      : "Pending"}
                </span>
              </li>
            );
          })}
        </ol>

        <p className="access-console__footnote">
          Passwords and enrollment secrets stay in this flow only. The session
          cookie is server-issued and inaccessible to JavaScript.
        </p>
      </aside>

      <main className="access-main">
        <div className="access-main__inner">
          <header className="access-heading">
            <p className="eyebrow">{eyebrow}</p>
            <h1>{title}</h1>
            <p>{description}</p>
          </header>
          {children}
        </div>
      </main>
    </div>
  );
}
