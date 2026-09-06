import { Button } from "@periapsis/ui/components/ui/button";

export function RouteErrorBoundary(): React.JSX.Element {
  return (
    <main className="access-main">
      <section
        className="access-main__inner"
        aria-labelledby="route-error-title"
      >
        <h1 id="route-error-title">This page could not be loaded</h1>
        <p>Reload the page to try again.</p>
        <Button type="button" onClick={() => window.location.reload()}>
          Reload page
        </Button>
      </section>
    </main>
  );
}
