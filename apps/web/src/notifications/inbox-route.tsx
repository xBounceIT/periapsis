import { notificationInboxApi } from "./inbox-api";
import { NotificationInboxProvider } from "./inbox-context";
import { NotificationInboxPage } from "./inbox-page";

export function NotificationInboxRoute(): React.JSX.Element {
  return (
    <NotificationInboxProvider api={notificationInboxApi}>
      <NotificationInboxPage />
    </NotificationInboxProvider>
  );
}
