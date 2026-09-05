import { createContext, useContext, type ReactNode } from "react";

import { alertDfirApi, type AlertDfirApi } from "./alert-dfir-api";

const AlertDfirApiContext = createContext<AlertDfirApi>(alertDfirApi);

export function AlertDfirApiProvider({
  api,
  children,
}: {
  api: AlertDfirApi;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <AlertDfirApiContext.Provider value={api}>
      {children}
    </AlertDfirApiContext.Provider>
  );
}

export function useAlertDfirApi(): AlertDfirApi {
  return useContext(AlertDfirApiContext);
}
