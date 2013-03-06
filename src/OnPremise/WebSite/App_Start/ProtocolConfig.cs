using BrockAllen.OAuth2;
using System.ServiceModel.Activation;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;
using Thinktecture.IdentityModel.Http;
using Thinktecture.IdentityModel.Tokens.Http;
using Thinktecture.IdentityServer.Protocols.WSTrust;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Web
{
    public class ProtocolConfig
    {
        public static void RegisterProtocols(HttpConfiguration httpConfiguration, RouteCollection routes, IConfigurationRepository configuration, IUserRepository users, IRelyingPartyRepository relyingParties)
        {
            var basicAuthConfig = CreateBasicAuthConfig(users);
            var clientAuthConfig = CreateClientAuthConfig();

            // require SSL for all web api endpoints
            httpConfiguration.MessageHandlers.Add(new RequireHttpsHandler());

            #region Protocols
            // federation metadata
            if (configuration.FederationMetadata.Enabled)
            {
                routes.MapRoute(
                    "FederationMetadata",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSFedMetadata,
                    new { controller = "FederationMetadata", action = "Generate" }
                );
            }

            //saml2 metadata
            if(configuration.Saml2Metadata.Enabled)
            {
                routes.MapRoute(
                "Saml2Metadata",
                Thinktecture.IdentityServer.Endpoints.Paths.Saml2Metadata,
                new { controller = "Saml2Metadata", action = "Generate" }
            );
            }

            // ws-federation
            if (configuration.WSFederation.Enabled && configuration.WSFederation.EnableAuthentication)
            {
                routes.MapRoute(
                    "wsfederation",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSFedIssuePage,
                    new { controller = "WSFederation", action = "issue" }
                );
            }

            // saml2
            if (configuration.Saml2.Enabled && configuration.Saml2.EnableAuthentication)
            {
                routes.MapRoute(
                    "saml2",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSSaml2Page,
                    new { controller = "Saml2", action = "issue" }
                );
            }

            // ws-federation HRD
            if (configuration.WSFederation.Enabled && configuration.WSFederation.EnableFederation)
            {
                routes.MapRoute(
                    "hrd",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSFedHRD,
                    new { controller = "Hrd", action = "issue" }
                );
                routes.MapRoute(
                    "hrd-select",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSFedHRDSelect,
                    new { controller = "Hrd", action = "Select" },
                    new { method = new HttpMethodConstraint("POST") }
                );
            }



            // oauth2 endpoint
            if (configuration.OAuth2.Enabled)
            {
                // authorize endpoint
                routes.MapRoute(
                    "oauth2authorize",
                    Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Authorize,
                    new { controller = "OAuth2Authorize", action = "index" }
                );

                // callback endpoint
                OAuth2Client.OAuthCallbackUrl = Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Callback;
                routes.MapRoute(
                    "oauth2callback",
                    Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Callback,
                    new { controller = "Hrd", action = "OAuthTokenCallback" }
                );

                // token endpoint
                routes.MapHttpRoute(
                    name: "oauth2token",
                    routeTemplate: Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Token,
                    defaults: new { controller = "OAuth2Token" },
                    constraints: null,
                    handler: new AuthenticationHandler(clientAuthConfig, httpConfiguration)
                );
            }

            // simple http endpoint
            if (configuration.SimpleHttp.Enabled)
            {
                routes.MapHttpRoute(
                    name: "simplehttp",
                    routeTemplate: Thinktecture.IdentityServer.Endpoints.Paths.SimpleHttp,
                    defaults: new { controller = "SimpleHttp" },
                    constraints: null,
                    handler: new AuthenticationHandler(basicAuthConfig, httpConfiguration)
                );
            }

            // ws-trust
            if (configuration.WSTrust.Enabled)
            {
                routes.Add(new ServiceRoute(
                    Thinktecture.IdentityServer.Endpoints.Paths.WSTrustBase,
                    new TokenServiceHostFactory(),
                    typeof(TokenServiceConfiguration))
                );
            }
            #endregion
        }

        public static AuthenticationConfiguration CreateBasicAuthConfig(IUserRepository userRepository)
        {
            var authConfig = new AuthenticationConfiguration
            {
                InheritHostClientIdentity = false,
                DefaultAuthenticationScheme = "Basic",
                ClaimsAuthenticationManager = new ClaimsTransformer()
            };

            authConfig.AddBasicAuthentication((userName, password) => userRepository.ValidateUser(userName, password));
            return authConfig;
        }

        public static AuthenticationConfiguration CreateClientAuthConfig()
        {
            var authConfig = new AuthenticationConfiguration
            {
                InheritHostClientIdentity = false,
                DefaultAuthenticationScheme = "Basic",
            };

            // accept arbitrary credentials on basic auth header,
            // validation will be done in the protocol endpoint
            authConfig.AddBasicAuthentication((id, secret) => true, retainPassword: true);
            return authConfig;
        }
    }
}