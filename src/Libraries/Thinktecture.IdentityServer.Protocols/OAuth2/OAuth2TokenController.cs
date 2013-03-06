/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.Composition;
using System.IdentityModel.Protocols.WSTrust;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Thinktecture.IdentityModel.Authorization;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.OAuth2
{
    public class OAuth2TokenController : ApiController
    {
        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IClientsRepository ClientsRepository { get; set; }

        public OAuth2TokenController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public OAuth2TokenController(IUserRepository userRepository, IConfigurationRepository configurationRepository, IClientsRepository clientsRepository)
        {
            UserRepository = userRepository;
            ConfigurationRepository = configurationRepository;
            ClientsRepository = clientsRepository;
        }

        public HttpResponseMessage Post(TokenRequest tokenRequest)
        {
            Tracing.Information("OAuth2 endpoint called.");

            Client client = null;
            if (!ValidateClient(out client))
            {
                Tracing.Error("Invalid client: " + ClaimsPrincipal.Current.Identity.Name);
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidClient);
            }

            Tracing.Information("Client: " + client.Name);

            var tokenType = ConfigurationRepository.Global.DefaultHttpTokenType;

            // validate scope
            EndpointReference appliesTo;
            try
            {
                appliesTo = new EndpointReference(tokenRequest.Scope);
                Tracing.Information("OAuth2 endpoint called for scope: " + tokenRequest.Scope);
            }
            catch
            {
                Tracing.Error("Malformed scope: " + tokenRequest.Scope);
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidScope);
            }

            // check grant type
            if (string.Equals(tokenRequest.Grant_Type, OAuth2Constants.GrantTypes.Password, System.StringComparison.Ordinal))
            {
                if (ConfigurationRepository.OAuth2.EnableResourceOwnerFlow)
                {
                    if (client.AllowResourceOwnerFlow)
                    {
                        return ProcessResourceOwnerCredentialRequest(tokenRequest.UserName, tokenRequest.Password, appliesTo, tokenType, client);
                    }
                    else
                    {
                        Tracing.Error("Client is not allowed to use the resource owner password flow:" + client.Name);
                    }
                }
            }

            Tracing.Error("invalid grant type: " + tokenRequest.Grant_Type);
            return OAuthErrorResponseMessage(OAuth2Constants.Errors.UnsupportedGrantType);
        }

        private HttpResponseMessage ProcessResourceOwnerCredentialRequest(string userName, string password, EndpointReference appliesTo, string tokenType, Client client)
        {
            Tracing.Information("Starting resource owner password credential flow for client: " + client.Name);

            if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
            {
                Tracing.Error("Invalid resource owner credentials for: " + appliesTo.Uri.AbsoluteUri);
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidGrant);
            }

            var auth = new AuthenticationHelper();
            ClaimsPrincipal principal;
            if (UserRepository.ValidateUser(userName, password))
            {
                principal = auth.CreatePrincipal(userName, "OAuth2",
                    new Claim[]
                        {
                            new Claim(Constants.Claims.Client, client.Name),
                            new Claim(Constants.Claims.Scope, appliesTo.Uri.AbsoluteUri)
                        });

                if (!ClaimsAuthorization.CheckAccess(principal, Constants.Actions.Issue, Constants.Resources.OAuth2))
                {
                    Tracing.Error("OAuth2 endpoint authorization failed for user: " + userName);
                    return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidGrant);
                }
            }
            else
            {
                Tracing.Error("Resource owner credential validation failed: " + userName);
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidGrant);
            }

            var sts = new STS();
            TokenResponse tokenResponse;
            if (sts.TryIssueToken(appliesTo, principal, tokenType, out tokenResponse))
            {
                var resp = Request.CreateResponse<TokenResponse>(HttpStatusCode.OK, tokenResponse);
                return resp;
            }
            else
            {
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidRequest);
            }
        }

        private HttpResponseMessage OAuthErrorResponseMessage(string error)
        {
            return Request.CreateErrorResponse(HttpStatusCode.BadRequest,
                string.Format("{{ \"{0}\": \"{1}\" }}", OAuth2Constants.Errors.Error, error));
        }

        private bool ValidateClient(out Client client)
        {
            client = null;

            if (!ClaimsPrincipal.Current.Identity.IsAuthenticated)
            {
                Tracing.Error("Anonymous client.");
                return false;
            }

            var passwordClaim = ClaimsPrincipal.Current.FindFirst("password");
            if (passwordClaim == null)
            {
                Tracing.Error("No password provided.");
                return false;
            }

            return ClientsRepository.ValidateAndGetClient(
                ClaimsPrincipal.Current.Identity.Name,
                passwordClaim.Value, 
                out client);
        }
    }
}
