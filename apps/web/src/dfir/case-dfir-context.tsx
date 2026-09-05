import { createContext, useContext, type ReactNode } from "react";

import { caseDfirApi, type CaseDfirApi } from "./case-dfir-api";

const CaseDfirApiContext = createContext<CaseDfirApi>(caseDfirApi);

export function CaseDfirApiProvider({
  api,
  children,
}: {
  api: CaseDfirApi;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <CaseDfirApiContext.Provider value={api}>
      {children}
    </CaseDfirApiContext.Provider>
  );
}

export function useCaseDfirApi(): CaseDfirApi {
  return useContext(CaseDfirApiContext);
}
