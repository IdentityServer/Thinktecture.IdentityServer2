/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.Web.Mvc;
using Thinktecture.IdentityServer.Protocols.OAuth2;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect.Endpoints
{
    public class OidcAuthorizeController : OidcAuthorizeControllerBase
    {
        public OidcAuthorizeController() : base()
        { }

        public OidcAuthorizeController(IOpenIdConnectClientsRepository clients, IStoredGrantRepository grants)
            : base(clients, grants)
        { }

        protected override ActionResult ShowConsent(ValidatedRequest validatedRequest)
        {
            Tracing.Information("OIDC Consent screen");

            return View("Consent", validatedRequest);
        }

        [HttpPost]
        protected override ActionResult HandleConsent(AuthorizeRequest request)
        {
            Tracing.Start("OIDC consent response");

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
            };

            return PerformGrant(validatedRequest);
        }
    }
}
