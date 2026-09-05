window.ui = SwaggerUIBundle({
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  displayRequestDuration: true,
  persistAuthorization: false,
  validatorUrl: null,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
  layout: "StandaloneLayout",
});
