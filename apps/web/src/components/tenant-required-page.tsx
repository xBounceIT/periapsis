import type { ReactNode } from "react";

export function TenantRequiredPage({
  children,
  label = "Tenant context required",
  title = "Select a tenant first.",
}: {
  children: ReactNode;
  label?: string;
  title?: string;
}): React.JSX.Element {
  return (
    <div className="content content--narrow">
      <section className="page-heading">
        <div>
          <p className="section-label">{label}</p>
          <h1>{title}</h1>
          <p>{children}</p>
        </div>
      </section>
    </div>
  );
}
