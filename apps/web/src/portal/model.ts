export const customerPortalRouteDescriptor = {
  path: "/portal",
  permissions: [
    "portal.alert.read",
    "portal.case.read",
    "portal.comment.public",
    "portal.contact.preference.manage",
  ] as const,
};
