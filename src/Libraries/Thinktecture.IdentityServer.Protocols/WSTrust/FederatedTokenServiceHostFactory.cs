using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Protocols.WSTrust
{
    /// <summary>
    /// Represents a token service host factory for a token service acting as federation provider.
    /// </summary>
    public class FederatedTokenServiceHostFactory : TokenServiceHostFactoryBase
    {
        [Import]
        public IIdentityProviderRepository IdentityProviderRepository { get; set; }

        public FederatedTokenServiceHostFactory()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
        {
            if (!ConfigurationRepository.WSTrust.EnableFederatedAuthentication)
            {
                throw new InvalidOperationException("WS-Trust Federation is not enabled.");
            }

            var config = CreateSecurityTokenServiceConfiguration(constructorString);
            var host = new WSTrustServiceHost(config, baseAddresses);

            // add behavior for load balancing support
            host.Description.Behaviors.Add(new UseRequestHeadersForMetadataAddressBehavior());

            // modify address filter mode for load balancing
            var serviceBehavior = host.Description.Behaviors.Find<ServiceBehaviorAttribute>();
            serviceBehavior.AddressFilterMode = AddressFilterMode.Any;

            // configure service certificate
            host.Credentials.ServiceCertificate.Certificate = ConfigurationRepository.Keys.DecryptionCertificate;

            // add and configure a mixed mode security endpoint
            if (ConfigurationRepository.WSTrust.Enabled &&
                ConfigurationRepository.WSTrust.EnableMixedModeSecurity &&
                !ConfigurationRepository.Global.DisableSSL)
            {
                var issuedTokenParameters = new IssuedSecurityTokenParameters
                {
                    KeyType = SecurityKeyType.SymmetricKey,
                };

                var securityElement = SecurityBindingElement.CreateIssuedTokenOverTransportBindingElement(issuedTokenParameters);

                securityElement.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;

                var binding = new CustomBinding
                {
                    Elements = 
                    {
                        securityElement,
                        new HttpsTransportBindingElement(),
                    }
                };

                host.AddServiceEndpoint(typeof(IWSTrust13SyncContract), binding, Endpoints.Paths.WSTrustMixedIssuedToken);
            }

            // add and configure a message security endpoint
            if (ConfigurationRepository.WSTrust.Enabled &&
                ConfigurationRepository.WSTrust.EnableMessageSecurity)
            {
                var issuedTokenParameters = new IssuedSecurityTokenParameters
                {
                    KeyType = SecurityKeyType.SymmetricKey,
                };

                var securityElement = SecurityBindingElement.CreateIssuedTokenBindingElement(issuedTokenParameters);

                securityElement.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;

                var binding = new CustomBinding
                {
                    Elements = 
                    {
                        securityElement,
                        new HttpTransportBindingElement(),
                    }
                };

                host.AddServiceEndpoint(typeof(IWSTrust13SyncContract), binding, Endpoints.Paths.WSTrustMessageIssuedToken);
            }

            return host;
        }

        protected override SecurityTokenServiceConfiguration CreateSecurityTokenServiceConfiguration(string constructorString)
        {
            var config = base.CreateSecurityTokenServiceConfiguration(constructorString);

            config.AudienceRestriction.AllowedAudienceUris.Add(new Uri(ConfigurationRepository.Global.IssuerUri));
            config.IssuerNameRegistry = new IdentityProviderIssuerNameRegistry(GetEnabledWSIdentityProviders());
            config.ClaimsAuthenticationManager = new FederatedClaimsAuthenticationManager();

            return config;
        }

        private IEnumerable<IdentityProvider> GetEnabledWSIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(p => p.Enabled && p.Type == IdentityProviderTypes.WSStar);
        }
    }
}
