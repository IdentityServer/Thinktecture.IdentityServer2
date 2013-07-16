using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Configuration;
using Thinktecture.IdentityModel.Web;
using System.Linq;

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
                    config.SigningCertificate).First();

                var response = OidcClient.HandleAuthorizeResponse(context.Request.QueryString);

                if (response.IsError)
                {
                    throw new InvalidOperationException(response.Error);
                }
                
                var cookie = new ProtectedCookie(ProtectionMode.MachineKey);
                var storedState = cookie.Read("oidcstate");

                var parts = storedState.Split('_');

                if (response.State != parts[0] || parts.Length != 2)
                {
                    throw new InvalidOperationException("state invalid.");
                }

                var returnUrl = parts[1];
                var redirectUri = context.Request.GetApplicationUrl() + "oidccallback";

                var tokenResponse = OidcClient.CallTokenEndpoint(
                    new Uri(tokenUrl),
                    new Uri(redirectUri),
                    response.Code,
                    clientId,
                    clientSecret);

                var identityClaims = OidcClient.ValidateIdentityToken(
                    tokenResponse.IdentityToken, 
                    issuerName, 
                    clientId, 
                    signingcert);

                var userInfoClaims = OidcClient.GetUserInfoClaims(
                    new Uri(userInfoUrl),
                    tokenResponse.AccessToken);

                // establish session
                var principal = new ClaimsPrincipal(new ClaimsIdentity(userInfoClaims, "oidc"));

                var sessionToken = new SessionSecurityToken(principal);
                FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionToken);

                // redirect local to return url
                context.Response.Redirect(returnUrl);
            }
        }

        public void Dispose()
        { }
    }
}
