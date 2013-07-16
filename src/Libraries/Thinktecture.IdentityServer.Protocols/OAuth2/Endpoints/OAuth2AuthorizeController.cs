/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.Composition;
using System.IdentityModel.Protocols.WSTrust;
using System.Security.Claims;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.OAuth2
{
    [ClaimsAuthorize(Constants.Actions.Issue, Constants.Resources.OAuth2)]
    public class OAuth2AuthorizeController : Controller
    {
        [Import]
        public IClientsRepository Clients { get; set; }

        [Import]
        public IConfigurationRepository Configuration { get; set; }

        [Import]
        public IRelyingPartyRepository RPRepository { get; set; }

        [Import]
        public ICodeTokenRepository CodeTokenRepository { get; set; }

        public OAuth2AuthorizeController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public OAuth2AuthorizeController(IConfigurationRepository configuration, IClientsRepository client, IRelyingPartyRepository rpRepository, ICodeTokenRepository codeTokenRepository)
        {
            Configuration = configuration;
            Clients = client;
            RPRepository = rpRepository;
            CodeTokenRepository = codeTokenRepository;
        }

        [ActionName("Index")]
        [HttpGet]
        public ActionResult HandleRequest(AuthorizeRequest request)
        {
            Tracing.Information("OAuth2 HandleRequest endpoint invoked");

            // check client
            Client client;
            var error = CheckRequest(request, out client);
            if (error != null) return error;

            RelyingParty rp;
            if (!RPRepository.TryGet(request.scope, out rp))
            {
                Tracing.Error("RP not found for scope : " + request.scope);
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidScope, request.response_type, request.state);
            }

            if (Configuration.OAuth2.EnableConsent)
            {
                // show resource name, uri and client name
                // client is trying to access resource on your behalf
                var vm = new OAuth2ConsentViewModel
                {
                    ResourceUri = rp.Realm.AbsoluteUri,
                    ResourceName = rp.Name,
                    ClientName = client.ClientId,
                    RefreshTokenEnabled = client.AllowRefreshToken
                };

                return View("ShowConsent", vm);
            }
            else
            {
                var grantResult = PerformGrant(request, client);
                if (grantResult != null) return grantResult;
            }

            // we don't know exactly why, so use ServerError
            Tracing.Error("Authorization Endpoint failed");
            return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidRequest, request.response_type, request.state);
        }

        [ActionName("Index")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult HandleConsentResponse(string button, AuthorizeRequest request)
        {
            Client client;
            var error = CheckRequest(request, out client);
            if (error != null) return error;

            if (button == "no")
            {
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.AccessDenied, request.response_type, request.state);
            }

            if (button == "yes")
            {
                var grantResult = PerformGrant(request, client);
                if (grantResult != null) return grantResult;
            }

            // todo: return appropiate error
            return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidRequest, request.response_type, request.state);
        }

        private ActionResult CheckRequest(AuthorizeRequest request, out Client client)
        {
            if (request == null)
            {
                client = null;
                ViewBag.Message = "Invalid request parameters";
                Tracing.Error(ViewBag.Message);
                return View("Error");
            }
            
            // validate client
            if (!Clients.TryGetClient(request.client_id, out client))
            {
                ViewBag.Message = "Invalid client_id : " + request.client_id;
                Tracing.Error(ViewBag.Message);
                return View("Error");
            }

            // validate redirect uri
            if (string.IsNullOrEmpty(request.redirect_uri) || 
                !string.Equals(request.redirect_uri, client.RedirectUri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
            {
                ViewBag.Message = "The redirect_uri in the request: " + request.redirect_uri + " did not match a registered redirect URI.";
                Tracing.Error(ViewBag.Message);
                return View("Error");
            }

            Uri redirectUrl;
            if (Uri.TryCreate(request.redirect_uri, UriKind.Absolute, out redirectUrl))
            {
                if (redirectUrl.Scheme == Uri.UriSchemeHttp)
                {
                    Tracing.Error("Redirect URI not over SSL : " + request.redirect_uri);
                    return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidRequest, string.Empty, request.state);
                }
            }
            else
            {
                Tracing.Error("Redirect URI not a valid URI : " + request.redirect_uri);
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidRequest, string.Empty, request.state);
            }

            if (String.IsNullOrWhiteSpace(request.response_type))
            {
                Tracing.Error("response_type is null or empty");
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidRequest, string.Empty, request.state);
            }

            // check response type (only code and token are supported)
            if (!request.response_type.Equals(OAuth2Constants.ResponseTypes.Token, StringComparison.Ordinal) &&
                !request.response_type.Equals(OAuth2Constants.ResponseTypes.Code, StringComparison.Ordinal))
            {
                Tracing.Error("response_type is not token or code: " + request.response_type);
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.UnsupportedResponseType, string.Empty, request.state);
            }

            // validate scope (must be a valid URI)
            Uri uri;
            if (!Uri.TryCreate(request.scope, UriKind.Absolute, out uri))
            {
                Tracing.Error("scope is not a URI: " + request.scope);
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidScope, request.response_type, request.state);
            }

            // validate if request grant type is allowed for client (implicit vs code flow)
            if (request.response_type.Equals(OAuth2Constants.ResponseTypes.Token) &&
                !client.AllowImplicitFlow)
            {
                Tracing.Error("response_type is token and client does not allow implicit flow. client: " + client.Name);
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.UnsupportedResponseType, request.response_type, request.state);
            }

            if (request.response_type.Equals(OAuth2Constants.ResponseTypes.Code) &&
                !client.AllowCodeFlow)
            {
                Tracing.Error("response_type is code and client does not allow code flow. client: " + client.Name);
                return ClientError(client.RedirectUri, OAuth2Constants.Errors.UnsupportedResponseType, request.response_type, request.state);
            }

            return null;
        }

        private ActionResult PerformGrant(AuthorizeRequest request, Client client)
        {
            // implicit grant
            if (request.response_type.Equals(OAuth2Constants.ResponseTypes.Token, StringComparison.Ordinal))
            {
                return PerformImplicitGrant(request, client);
            }

            // authorization code grant
            if (request.response_type.Equals(OAuth2Constants.ResponseTypes.Code, StringComparison.Ordinal))
            {
                return PerformAuthorizationCodeGrant(request, client);
            }

            return null;
        }

        private ActionResult PerformAuthorizationCodeGrant(AuthorizeRequest request, Client client)
        {
            var code = CodeTokenRepository.AddCode(CodeTokenType.AuthorizationCode, client.ID, ClaimsPrincipal.Current.Identity.Name, request.scope);
            var tokenString = string.Format("code={0}", code);

            if (!string.IsNullOrEmpty(request.state))
            {
                tokenString = string.Format("{0}&state={1}", tokenString, Server.UrlEncode(request.state));
            }

            var redirectString = string.Format("{0}?{1}",
                        client.RedirectUri.AbsoluteUri,
                        tokenString);

            return Redirect(redirectString);
        }

        private ActionResult PerformImplicitGrant(AuthorizeRequest request, Client client)
        {
            var sts = new STS();

            TokenResponse tokenResponse;
            if (sts.TryIssueToken(
                    new EndpointReference(request.scope),
                    ClaimsPrincipal.Current,
                    Configuration.Global.DefaultHttpTokenType,
                    out tokenResponse))
            {
                var tokenString = string.Format("access_token={0}&token_type={1}&expires_in={2}",
                        tokenResponse.AccessToken,
                        tokenResponse.TokenType,
                        tokenResponse.ExpiresIn);

                if (!string.IsNullOrEmpty(request.state))
                {
                    tokenString = string.Format("{0}&state={1}", tokenString, Server.UrlEncode(request.state));
                }

                var redirectString = string.Format("{0}#{1}",
                        client.RedirectUri.AbsoluteUri,
                        tokenString);

                return Redirect(redirectString);
            }

            // return right error code
            return ClientError(client.RedirectUri, OAuth2Constants.Errors.InvalidRequest, request.response_type, request.state);
        }

        private ActionResult ClientError(Uri redirectUri, string error, string responseType, string state = null)
        {
            string url;
            string separator = "?";

            if (responseType == OAuth2Constants.ResponseTypes.Token)
            {
                separator = "#";
            }

            if (string.IsNullOrEmpty(state))
            {
                url = string.Format("{0}{1}error={2}", redirectUri.AbsoluteUri, separator, error);
            }
            else
            {
                url = string.Format("{0}{1}error={2}&state={3}", redirectUri.AbsoluteUri, separator, error, Server.UrlEncode(state));
            }

            return new RedirectResult(url);
        }
    }
}
