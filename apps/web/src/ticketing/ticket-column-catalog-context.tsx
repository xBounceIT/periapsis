import { createContext, useContext, type ReactNode } from "react";

import {
  ticketColumnCatalogApi,
  type TicketColumnCatalogApi,
} from "../lib/ticket-column-catalog-api";

const TicketColumnCatalogApiContext = createContext<TicketColumnCatalogApi>(
  ticketColumnCatalogApi,
);

export function TicketColumnCatalogApiProvider({
  api,
  children,
}: {
  api: TicketColumnCatalogApi;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <TicketColumnCatalogApiContext.Provider value={api}>
      {children}
    </TicketColumnCatalogApiContext.Provider>
  );
}

export function useTicketColumnCatalogApi(): TicketColumnCatalogApi {
  return useContext(TicketColumnCatalogApiContext);
}
