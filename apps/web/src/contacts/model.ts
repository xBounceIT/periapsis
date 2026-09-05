export const contactAdministrationRouteDescriptor = {
  path: "/tenant/contacts",
  permissions: ["contact.read", "contact_group.read"] as const,
};
