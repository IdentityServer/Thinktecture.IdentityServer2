using BrockAllen.OAuth2;
using System;
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
            // require SSL for all web api endpoints
            if (!configuration.Global.DisableSSL)
            {
                httpConfiguration.MessageHandlers.Add(new RequireHttpsHandler());
            }

            #region Protocols
            // federation metadata
            if (configuration.FederationMetadata.Enabled)
            {
                 routes.MapRoute(
                    "FederationMetadataRP",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSFedRPMetadata,
                    new { controller = "FederationMetadata", action = "GenerateRPMetadata" }
                );

                routes.MapRoute(
                    "FederationMetadata",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSFedMetadata,
                    new { controller = "FederationMetadata", action = "Generate" }
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
                routes.MapRoute(
                    "hrd-signout-redirect",
                    Thinktecture.IdentityServer.Endpoints.Paths.WSFedHRDSignoutRedirect,
                    new { controller = "Hrd", action = "SignoutRedirect" }
                );

                // callback endpoint
                OAuth2Client.OAuthCallbackUrl = Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Callback;
                if (!String.IsNullOrWhiteSpace(configuration.Global.PublicHostName))
                {
                    var ub = new UriBuilder(Uri.UriSchemeHttps, configuration.Global.PublicHostName, configuration.Global.HttpsPort);
                    OAuth2Client.OAuthCallbackOrigin = ub.Uri;
                }
                routes.MapRoute(
                    "oauth2callback",
                    Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Callback,
                    new { controller = "Hrd", action = "OAuthTokenCallback" }
                );
            }

            // oauth2 endpoint
            if (configuration.OAuth2.Enabled)
            {
                // authorize endpoint
                routes.MapRoute(
                    "oauth2authorize",
                    Endpoints.Paths.OAuth2Authorize,
                    new { controller = "OAuth2Authorize", action = "index" }
                );

                // token endpoint
                routes.MapHttpRoute(
                    name: "oauth2token",
                    routeTemplate: Endpoints.Paths.OAuth2Token,
                    defaults: new { controller = "OAuth2Token" },
                    constraints: null,
                    handler: new AuthenticationHandler(CreateClientAuthConfig(configuration), httpConfiguration)
                );
            }

            // open id connect
            if (configuration.OpenIdConnect.Enabled &&
                configuration.Keys.SigningCertificate != null)
            {
                // authorize endpoint
                routes.MapRoute(
                    "oidcauthorize",
                    Endpoints.Paths.OidcAuthorize,
                    new { controller = "OidcAuthorize", action = "index" }
                );

                // token endpoint
                routes.MapHttpRoute(
                    name: "oidctoken",
                    routeTemplate: Endpoints.Paths.OidcToken,
                    defaults: new { controller = "OidcToken" },
                    constraints: null,
                    handler: new AuthenticationHandler(CreateClientAuthConfig(configuration), httpConfiguration)
                );

                // userinfo endpoint
                routes.MapHttpRoute(
                    name: "oidcuserinfo",
                    routeTemplate: Endpoints.Paths.OidcUserInfo,
                    defaults: new { controller = "OidcUserInfo" },
                    constraints: null,
                    handler: new AuthenticationHandler(CreateUserInfoAuthConfig(configuration), httpConfiguration)
                );
            }

            // adfs integration
            if (configuration.AdfsIntegration.Enabled)
            {
                routes.MapHttpRoute(
                    name: "adfs",
                    routeTemplate: Thinktecture.IdentityServer.Endpoints.Paths.AdfsIntegration,
                    defaults: new { controller = "Adfs" }
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
                    handler: new AuthenticationHandler(CreateBasicAuthConfig(configuration, users), httpConfiguration)
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

                if (configuration.WSTrust.EnableFederatedAuthentication)
                {
                    routes.Add(new ServiceRoute(
                        Thinktecture.IdentityServer.Endpoints.Paths.WSTrustFederationBase,
                        new FederatedTokenServiceHostFactory(),
                        typeof(TokenServiceConfiguration))
                    );
                }
            }
            #endregion
        }

        public static AuthenticationConfiguration CreateBasicAuthConfig(IConfigurationRepository configuration, IUserRepository userRepository)
        {
            var authConfig = new AuthenticationConfiguration
            {
                InheritHostClientIdentity = false,
                RequireSsl = !configuration.Global.DisableSSL,
                ClaimsAuthenticationManager = new ClaimsTransformer()
            };

            authConfig.AddBasicAuthentication((userName, password) => userRepository.ValidateUser(userName, password));
            return authConfig;
        }

        public static AuthenticationConfiguration CreateClientAuthConfig(IConfigurationRepository configuration)
        {
            var authConfig = new AuthenticationConfiguration
            {
                InheritHostClientIdentity = false,
                RequireSsl = !configuration.Global.DisableSSL,
            };

            // accept arbitrary credentials on basic auth header,
            // validation will be done in the protocol endpoint
            authConfig.AddBasicAuthentication((id, secret) => true, retainPassword: true);
            return authConfig;
        }

        public static AuthenticationConfiguration CreateUserInfoAuthConfig(IConfigurationRepository configuration)
        {
            var userInfoAuth = new AuthenticationConfiguration
            {
                RequireSsl = !configuration.Global.DisableSSL,
                InheritHostClientIdentity = false
            };

            userInfoAuth.AddJsonWebToken(
                issuer: configuration.Global.IssuerUri,
                audience: configuration.Global.IssuerUri + "/userinfo",
                signingCertificate: configuration.Keys.SigningCertificate);

            return userInfoAuth;
        }
    }
}