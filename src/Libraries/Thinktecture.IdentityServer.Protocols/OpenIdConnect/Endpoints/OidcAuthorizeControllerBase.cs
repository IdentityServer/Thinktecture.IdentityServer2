/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.Composition;
using System.Security.Claims;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Protocols.OAuth2;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    [Authorize]
    public abstract class OidcAuthorizeControllerBase : Controller
    {
        [Import]
        public IOpenIdConnectClientsRepository Clients { get; set; }

        [Import]
        public IStoredGrantRepository Grants { get; set; }

        protected abstract ActionResult ShowConsent(ValidatedRequest validatedRequest);
        protected abstract ActionResult HandleConsent(AuthorizeRequest request);
        
        public OidcAuthorizeControllerBase()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public OidcAuthorizeControllerBase(IOpenIdConnectClientsRepository clients, IStoredGrantRepository grants)
        {
            Clients = clients;
            Grants = grants;
        }

        public ActionResult Index(AuthorizeRequest request)
        {
            Tracing.Start("OIDC Authorize Endpoint");

            ValidatedRequest validatedRequest;

            try
            {
                var validator = new AuthorizeRequestValidator(Clients);
                validatedRequest = validator.Validate(request);
            }
            catch (AuthorizeRequestValidationException ex)
            {
                Tracing.Error("Aborting OAuth2 authorization request");
                return this.AuthorizeValidationError(ex);
            }

            if (validatedRequest.Client.RequireConsent)
            {
                return ShowConsent(validatedRequest);
            }

            return PerformGrant(validatedRequest);
        }

        protected virtual ActionResult PerformGrant(ValidatedRequest validatedRequest)
        {
            // implicit grant
            if (validatedRequest.ResponseType.Equals(OAuth2Constants.ResponseTypes.Token, StringComparison.Ordinal))
            {
                return PerformImplicitGrant(validatedRequest);
            }

            // authorization code grant
            if (validatedRequest.ResponseType.Equals(OAuth2Constants.ResponseTypes.Code, StringComparison.Ordinal))
            {
                return PerformAuthorizationCodeGrant(validatedRequest);
            }

            return null;
        }

        protected virtual ActionResult PerformAuthorizationCodeGrant(ValidatedRequest validatedRequest)
        {
            Tracing.Information("Processing authorization code request");

            var grant = StoredGrant.CreateAuthorizationCode(
                validatedRequest.Client.ClientId,
                ClaimsPrincipal.Current.Identity.Name,
                validatedRequest.Scopes,
                validatedRequest.RedirectUri,
                60);

            Grants.Add(grant);

            var tokenString = string.Format("code={0}", grant.GrantId);

            if (!string.IsNullOrWhiteSpace(validatedRequest.State))
            {
                tokenString = string.Format("{0}&state={1}", tokenString, Server.UrlEncode(validatedRequest.State));
            }

            var redirectString = string.Format("{0}?{1}",
                        validatedRequest.RedirectUri,
                        tokenString);

            return Redirect(redirectString);
        }

        protected virtual ActionResult PerformImplicitGrant(ValidatedRequest validatedRequest)
        {
            throw new NotImplementedException();
        }
    }
}
