import { createContext, useContext, type ReactNode } from "react";

import { ticketBulkApi, type TicketBulkApi } from "../lib/ticket-bulk-api";

const TicketBulkApiContext = createContext<TicketBulkApi>(ticketBulkApi);

export function TicketBulkApiProvider({
  api,
  children,
}: {
  api: TicketBulkApi;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <TicketBulkApiContext.Provider value={api}>
      {children}
    </TicketBulkApiContext.Provider>
  );
}

export function useTicketBulkApi(): TicketBulkApi {
  return useContext(TicketBulkApiContext);
}
