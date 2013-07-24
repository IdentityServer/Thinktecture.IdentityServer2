using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class MenuViewModel
    {
        public MenuViewModel(IConfigurationRepository configuration)
        {
            this.ShowIdentityProviders = configuration.WSFederation.Enabled && configuration.WSFederation.EnableFederation;
            this.ShowOpenIdConnectClients = configuration.OpenIdConnect.Enabled;
            this.ShowOAuthClients = configuration.OAuth2.Enabled;
            this.ShowOAuthTokens = 
                configuration.OAuth2.Enabled && 
                (configuration.OAuth2.EnableCodeFlow || configuration.OAuth2.EnableResourceOwnerFlow);
            this.ShowClientCerts = configuration.Global.EnableClientCertificateAuthentication;
            this.ShowIdentityDelegation = configuration.WSTrust.Enabled && configuration.WSTrust.EnableDelegation;
        }

        public bool ShowIdentityProviders { get; private set; }
        public bool ShowOpenIdConnectClients { get; private set; }
        public bool ShowOAuthClients { get; private set; }
        public bool ShowOAuthTokens { get; private set; }
        public bool ShowClientCerts { get; private set; }
        public bool ShowIdentityDelegation { get; private set; }
    }
}