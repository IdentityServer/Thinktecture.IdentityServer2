/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.Composition;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Thinktecture.IdentityModel.Authorization.WebApi;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.SimpleHTTP
{
    [ClaimsAuthorize(Constants.Actions.Issue, Constants.Resources.SimpleHttp)]
    public class SimpleHttpController : ApiController
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public SimpleHttpController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public SimpleHttpController(IConfigurationRepository configurationRepository)
        {
            ConfigurationRepository = configurationRepository;
        }

        public HttpResponseMessage Get(HttpRequestMessage request)
        {
            Tracing.Information("Simple HTTP endpoint called.");

            var query = request.GetQueryNameValuePairs();
            var auth = new AuthenticationHelper();

            var realm = query.FirstOrDefault(p => p.Key.Equals("realm", System.StringComparison.OrdinalIgnoreCase)).Value;
            var tokenType = query.FirstOrDefault(p => p.Key.Equals("tokenType", System.StringComparison.OrdinalIgnoreCase)).Value;

            if (string.IsNullOrWhiteSpace(realm))
            {
                return request.CreateErrorResponse(HttpStatusCode.BadRequest, "realm parameter is missing.");
            }

            EndpointReference appliesTo;
            try
            {
                appliesTo = new EndpointReference(realm);
                Tracing.Information("Simple HTTP endpoint called for realm: " + realm);
            }
            catch
            {
                Tracing.Error("Malformed realm: " + realm);
                return request.CreateErrorResponse(HttpStatusCode.BadRequest, "malformed realm name.");
            }

            if (string.IsNullOrWhiteSpace(tokenType))
            {
                tokenType = ConfigurationRepository.Global.DefaultHttpTokenType;
            }
            else
            {
                if (tokenType.Equals("jwt"))
                {
                    tokenType = TokenTypes.JsonWebToken;
                }
                else if (tokenType.Equals("swt"))
                {
                    tokenType = TokenTypes.SimpleWebToken;
                }
                else if (tokenType.Equals("saml11"))
                {
                    tokenType = TokenTypes.Saml11TokenProfile11;
                }
                else if (tokenType.Equals("saml2"))
                {
                    tokenType = TokenTypes.Saml2TokenProfile11;
                }
            }

            Tracing.Verbose("Token type: " + tokenType);

            TokenResponse tokenResponse;
            var sts = new STS();
            if (sts.TryIssueToken(appliesTo, ClaimsPrincipal.Current, tokenType, out tokenResponse))
            {
                var resp = request.CreateResponse<TokenResponse>(HttpStatusCode.OK, tokenResponse);
                return resp;
            }
            else
            {
                return request.CreateErrorResponse(HttpStatusCode.BadRequest, "invalid request.");
            }
        }
    }
}
