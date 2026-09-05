import { createContext, useContext, type ReactNode } from "react";

import { ticketingApi, type TicketingApi } from "../lib/ticketing-api";

const TicketingApiContext = createContext<TicketingApi>(ticketingApi);

export function TicketingApiProvider({
  api,
  children,
}: {
  api: TicketingApi;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <TicketingApiContext.Provider value={api}>
      {children}
    </TicketingApiContext.Provider>
  );
}

export function useTicketingApi(): TicketingApi {
  return useContext(TicketingApiContext);
}
