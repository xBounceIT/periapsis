export const tenantFederationRouteDescriptor = {
  path: "/tenant/federated-identity-providers",
  label: "Federated providers",
  permissions: ["identity_provider.read"] as const,
};
