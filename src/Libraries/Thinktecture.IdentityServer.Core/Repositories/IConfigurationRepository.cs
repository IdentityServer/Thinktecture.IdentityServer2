using Thinktecture.IdentityServer.Models.Configuration;

namespace Thinktecture.IdentityServer.Repositories
{
    public interface IConfigurationRepository
    {
        bool SupportsWriteAccess { get; }

        GlobalConfiguration Global { get; set; }
        DiagnosticsConfiguration Diagnostics { get; set; }
        KeyMaterialConfiguration Keys { get; set; }

        WSFederationConfiguration WSFederation { get; set; }
        FederationMetadataConfiguration FederationMetadata { get; set; }
        WSTrustConfiguration WSTrust { get; set; }
        OAuth2Configuration OAuth2 { get; set; }
        AdfsIntegrationConfiguration AdfsIntegration { get; set; }
        SimpleHttpConfiguration SimpleHttp { get; set; }
        OpenIdConnectConfiguration OpenIdConnect { get; set; }
    }
}
