import { useEffect } from "react";

type WarningCondition = boolean | Readonly<{ current: boolean }>;

export function useBeforeUnloadWarning(
  condition: WarningCondition = true,
): void {
  useEffect(() => {
    function warnBeforeLeaving(event: BeforeUnloadEvent): void {
      const shouldWarn =
        typeof condition === "boolean" ? condition : condition.current;
      if (shouldWarn) event.preventDefault();
    }

    window.addEventListener("beforeunload", warnBeforeLeaving);
    return () => window.removeEventListener("beforeunload", warnBeforeLeaving);
  }, [condition]);
}
