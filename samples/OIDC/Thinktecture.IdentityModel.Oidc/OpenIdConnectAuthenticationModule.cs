using System;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Web;
using Thinktecture.IdentityModel.Web;

namespace Thinktecture.IdentityModel.Oidc
{
    public class OpenIdConnectAuthenticationModule : IHttpModule
    {
        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += OnAuthenticateRequestRequest;
            context.EndRequest += OnEndRequest;
        }

        void OnEndRequest(object sender, EventArgs e)
        {
            var context = HttpContext.Current;

            if (context.Response.StatusCode == 401 &&
                !context.User.Identity.IsAuthenticated &&
                !context.Response.SuppressFormsAuthenticationRedirect)
            {
                var config = OidcClientConfigurationSection.Instance;

                var authorizeUrl = config.Endpoints.Authorize;
                var clientId = config.ClientId;
                var scopes = "openid " + config.Scope;
                var state = Guid.NewGuid().ToString("N");
                var returnUrl = context.Request.RawUrl;
                var redirectUri = context.Request.GetApplicationUrl() + "oidccallback";

                var authorizeUri = OidcClient.GetAuthorizeUrl(
                    new Uri(authorizeUrl),
                    new Uri(redirectUri),
                    clientId,
                    scopes,
                    state);

                var cookie = new ProtectedCookie(ProtectionMode.MachineKey);
                cookie.Write("oidcstate", state + "_" + returnUrl, DateTime.UtcNow.AddHours(1));

                context.Response.Redirect(authorizeUri.AbsoluteUri);
            }
        }

        void OnAuthenticateRequestRequest(object sender, EventArgs e)
        {
            var context = HttpContext.Current;

            if (context.Request.AppRelativeCurrentExecutionFilePath.Equals("~/oidccallback", StringComparison.OrdinalIgnoreCase))
            {
                var config = OidcClientConfigurationSection.Instance;

                var tokenUrl = config.Endpoints.Token;
                var userInfoUrl = config.Endpoints.UserInfo;
                var clientId = config.ClientId;
                var clientSecret = config.ClientSecret;
                var issuerName = config.IssuerName;
                var signingcert = X509.LocalMachine.TrustedPeople.SubjectDistinguishedName.Find(
                    config.SigningCertificate, false).First();

                // parse OIDC authorize response
                var response = OidcClient.HandleAuthorizeResponse(context.Request.QueryString);

                if (response.IsError)
                {
                    throw new InvalidOperationException(response.Error);
                }

                // read and parse state cookie
                var cookie = new ProtectedCookie(ProtectionMode.MachineKey);
                var storedState = cookie.Read("oidcstate");
                ProtectedCookie.Delete("oidcstate");

                var separator = storedState.IndexOf('_');
                if (separator == -1)
                {
                    throw new InvalidOperationException("state invalid.");
                }

                var state = storedState.Substring(0, separator);
                var returnUrl = storedState.Substring(separator + 1);
                var redirectUri = context.Request.GetApplicationUrl() + "oidccallback";

                // validate state
                if (response.State != state)
                {
                    throw new InvalidOperationException("state invalid.");
                }

                // call token endpoint and retrieve id and access token (and maybe a refresh token)
                var tokenResponse = OidcClient.CallTokenEndpoint(
                    new Uri(tokenUrl),
                    new Uri(redirectUri),
                    response.Code,
                    clientId,
                    clientSecret);

                // validate identity token
                var identityClaims = OidcClient.ValidateIdentityToken(
                    tokenResponse.IdentityToken,
                    issuerName,
                    clientId,
                    signingcert);

                // retrieve user info data
                var userInfoClaims = OidcClient.GetUserInfoClaims(
                    new Uri(userInfoUrl),
                    tokenResponse.AccessToken);

                // create identity
                var id = new ClaimsIdentity(userInfoClaims, "oidc");

                if (!string.IsNullOrWhiteSpace(tokenResponse.RefreshToken))
                {
                    id.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));
                }

                // create principal
                var principal = new ClaimsPrincipal(id);
                var transformedPrincipal = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager.Authenticate(string.Empty, principal);

                // establish session
                var sessionToken = new SessionSecurityToken(transformedPrincipal);
                FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionToken);

                // redirect local to return url
                if (!string.IsNullOrWhiteSpace(returnUrl))
                {
                    context.Response.Redirect(returnUrl);
                }
                else
                {
                    context.Response.Redirect("~/");
                }
            }
        }

        public void Dispose()
        { }
    }
}