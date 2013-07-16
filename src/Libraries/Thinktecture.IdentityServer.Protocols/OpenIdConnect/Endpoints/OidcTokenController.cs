using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Protocols.OAuth2;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    public class OidcTokenController : ApiController
    {
        [Import]
        public IStoredGrantRepository Grants { get; set; }

        [Import]
        public IClientsRepository Clients { get; set; }

        [Import]
        public IConfigurationRepository ServerConfiguration { get; set; }

        public OidcTokenController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public HttpResponseMessage Post(TokenRequest request)
        {
            Tracing.Start("OIDC Token Endpoint");

            ValidatedRequest validatedRequest;

            try
            {
                var validator = new TokenRequestValidator(Clients, Grants);
                validatedRequest = validator.Validate(request, ClaimsPrincipal.Current);
            }
            catch (TokenRequestValidationException ex)
            {
                Tracing.Error("Aborting OIDC token request");
                return Request.CreateOAuthErrorResponse(ex.OAuthError);
            }

            // switch over the grant type
            if (validatedRequest.GrantType.Equals(OAuth2Constants.GrantTypes.AuthorizationCode))
            {
                return ProcessAuthorizationCodeRequest(validatedRequest);
            }
            //else if (string.Equals(validatedRequest.GrantType, OAuth2Constants.GrantTypes.RefreshToken))
            //{
            //    return ProcessRefreshTokenRequest(validatedRequest);
            //}
            
            Tracing.Error("invalid grant type: " + request.Grant_Type);
            return Request.CreateOAuthErrorResponse(OAuth2Constants.Errors.UnsupportedGrantType);
        }

        private HttpResponseMessage ProcessAuthorizationCodeRequest(ValidatedRequest validatedRequest)
        {
            Tracing.Information("Processing authorization code request");

            var tokenService = new OidcTokenService(ServerConfiguration.Global.IssuerUri, ServerConfiguration.Keys.SigningCertificate);
            var response = tokenService.CreateTokenResponse(validatedRequest);

            return Request.CreateTokenResponse(response);
        } 
    }
}
