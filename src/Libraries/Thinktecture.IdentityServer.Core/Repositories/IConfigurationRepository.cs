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
        Saml2Configuration Saml2 { get; set; }
        FederationMetadataConfiguration FederationMetadata { get; set; }
        Saml2MetadataConfiguration Saml2Metadata { get; set; }
        WSTrustConfiguration WSTrust { get; set; }
        OAuth2Configuration OAuth2 { get; set; }
        SimpleHttpConfiguration SimpleHttp { get; set; }
    }
}
