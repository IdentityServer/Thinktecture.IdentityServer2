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

        public OAuth2AuthorizeController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public OAuth2AuthorizeController(IConfigurationRepository configuration, IClientsRepository client, IRelyingPartyRepository rpRepository)
        {
            Configuration = configuration;
            Clients = client;
            RPRepository = rpRepository;
        }

        private ActionResult CheckRequest(AuthorizeRequest request, out Client client)
        {
            // validate client
            if (!Clients.TryGetClient(request.client_id, out client))
            {
                ViewBag.Message = "Invalid client_id : " + request.client_id;
                return View("Error");
            }

            // validate redirect uri
            if (string.IsNullOrEmpty(request.redirect_uri) || !string.Equals(request.redirect_uri, client.RedirectUri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
            {
                ViewBag.Message = "The redirect_uri in the request: " + request.redirect_uri + " did not match a registered redirect URI.";
                return View("Error");
            }

            // validate scope (must be a valid URI)
            Uri uri;
            if (!Uri.TryCreate(request.scope, UriKind.Absolute, out uri))
            {
                return Error(client.RedirectUri, OAuth2Constants.Errors.InvalidScope, request.state);
            }

            return null;
        }

        [ActionName("Index")]
        [HttpGet]
        public ActionResult HandleRequest(AuthorizeRequest request)
        {
            //
            // first round of validation:
            // missing, invalid, or mismatching redirection URI or
            // missing or invalid client id
            // show error page to user
            //

            Client client;
            var error = CheckRequest(request, out client);
            if (error != null) return error;

            // implicit grant
            if (request.response_type.Equals(OAuth2Constants.ResponseTypes.Token, StringComparison.Ordinal) ||
                request.response_type.Equals(OAuth2Constants.ResponseTypes.Code, StringComparison.Ordinal))
            {
                if (Configuration.OAuth2.EnableConsent)
                {
                    RelyingParty rp;
                    if (RPRepository.TryGet(request.scope, out rp))
                    {
                        // show resource name, uri and client name
                        // client is trying to access resource on your behalf
                        var vm = new OAuth2ConsentViewModel
                        {
                            ResourceUri = rp.Realm.AbsoluteUri,
                            ResourceName = rp.Name,
                            ClientName = client.ClientId
                        };

                        return View("ShowConsent", vm);
                    }
                }
                else
                {
                    var grantResult = PerformGrant(request, client);
                    if (grantResult != null) return grantResult;
                }
            }

            // todo: return appropiate error
            return Error(client.RedirectUri, OAuth2Constants.Errors.UnsupportedResponseType, request.state);
        }

        [ActionName("Index")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult HandleResponse(string button, AuthorizeRequest request)
        {
            Client client;
            var error = CheckRequest(request, out client);
            if (error != null) return error;

            if (button == "no")
            {
                return Error(client.RedirectUri, OAuth2Constants.Errors.AccessDenied, request.state);
            }

            if (button == "yes")
            {
                var grantResult = PerformGrant(request, client);
                if (grantResult != null) return grantResult;
            }

            // todo: return appropiate error
            return Error(client.RedirectUri, OAuth2Constants.Errors.UnsupportedResponseType, request.state);
        }

        private ActionResult PerformGrant(AuthorizeRequest request, Client client)
        {
            // implicit grant
            if (request.response_type.Equals(OAuth2Constants.ResponseTypes.Token, StringComparison.Ordinal))
            {
                return HandleImplicitGrant(request, client);
            }

            // authorization code grant
            if (request.response_type.Equals(OAuth2Constants.ResponseTypes.Code, StringComparison.Ordinal))
            {
                return HandleAuthorizationCodeGrant(request, client);
            }

            return null;
        }

        private ActionResult HandleAuthorizationCodeGrant(AuthorizeRequest request, Client client)
        {
            throw new System.NotImplementedException();
        }

        private ActionResult HandleImplicitGrant(AuthorizeRequest request, Client client)
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
                    tokenString = string.Format("{0}&state={1}", tokenString, request.state);
                }

                var redirectString = string.Format("{0}#{1}",
                        client.RedirectUri.AbsoluteUri,
                        tokenString);

                return Redirect(redirectString);
            }

            // return right error code
            return Error(client.RedirectUri, OAuth2Constants.Errors.InvalidRequest, request.state);
        }

        private ActionResult Error(Uri redirectUri, string error, string state = null)
        {
            string url;

            if (string.IsNullOrEmpty(state))
            {
                url = string.Format("{0}#error={1}", redirectUri.AbsoluteUri, error);
            }
            else
            {
                url = string.Format("{0}#error={1}&state={2}", redirectUri.AbsoluteUri, error, state);
            }

            return new RedirectResult(url);
        }
    }
}
