import { createContext, useContext, type ReactNode } from "react";

import {
  ticketExportApi,
  type TicketExportApi,
} from "../lib/ticket-export-api";

const TicketExportApiContext = createContext<TicketExportApi>(ticketExportApi);

export function TicketExportApiProvider({
  api,
  children,
}: {
  api: TicketExportApi;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <TicketExportApiContext.Provider value={api}>
      {children}
    </TicketExportApiContext.Provider>
  );
}

export function useTicketExportApi(): TicketExportApi {
  return useContext(TicketExportApiContext);
}
