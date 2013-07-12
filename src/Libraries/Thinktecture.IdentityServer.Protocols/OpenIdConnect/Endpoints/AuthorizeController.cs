﻿using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Protocols.OAuth2;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    public class AuthorizeController : Controller
    {
        [Import]
        public IClientsRepository Clients { get; set; }

        public AuthorizeController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public AuthorizeController(IClientsRepository clients)
        {
            Clients = clients;
        }

        public ActionResult Index(AuthorizeRequest request)
        {
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

            // consent - todo

            return PerformGrant(validatedRequest);
        }

        private ActionResult PerformGrant(ValidatedRequest validatedRequest)
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

        private ActionResult PerformAuthorizationCodeGrant(ValidatedRequest validatedRequest)
        {
            var grant = Grant.CreateAuthorizationCode(
                validatedRequest.Client.ClientId,
                ClaimsPrincipal.Current.Identity.Name,
                validatedRequest.Scopes,
                validatedRequest.RedirectUri);

            // store grant - todo

            var tokenString = string.Format("code={0}", grant.HandleId);

            if (!string.IsNullOrWhiteSpace(validatedRequest.State))
            {
                tokenString = string.Format("{0}&state={1}", tokenString, Server.UrlEncode(validatedRequest.State));
            }

            var redirectString = string.Format("{0}?{1}",
                        validatedRequest.RedirectUri,
                        tokenString);

            return Redirect(redirectString);
        }

        private ActionResult PerformImplicitGrant(ValidatedRequest validatedRequest)
        {
            throw new NotImplementedException();
        }
    }
}