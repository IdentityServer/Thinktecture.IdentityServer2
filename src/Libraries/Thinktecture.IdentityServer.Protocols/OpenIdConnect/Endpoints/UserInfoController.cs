/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IdentityModel.Protocols.WSTrust;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    [Authorize]
    public class OidcUserInfoController : ApiController
    {
        [Import]
        public IClaimsRepository ClaimsRepository { get; set; }

        public OidcUserInfoController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public OidcUserInfoController(IClaimsRepository claimsRepository)
        {
            ClaimsRepository = claimsRepository;
        }

        public HttpResponseMessage Get()
        {
            //var requestClaims = new RequestClaimCollection();

            //var scopes = ClaimsPrincipal.Current.FindAll(OAuth2Constants.Scope);
            //foreach (var scope in scopes)
            //{
            //    if (OidcConstants.Mappings.ContainsKey(scope.Value))
            //    {
            //        foreach (var oidcClaim in OidcConstants.Mappings[scope.Value])
            //        {
            //            requestClaims.Add(new RequestClaim(oidcClaim));
            //        }
            //    }
            //    else
            //    {
            //        Request.CreateErrorResponse(HttpStatusCode.BadRequest, "invalid scope");
            //    }
            //}

            var details = new RequestDetails { IsOpenIdRequest = true };
            //details.ClaimsRequested = true;
            //details.RequestClaims = requestClaims;

            var principal = Principal.Create("OpenIdConnect",
                new Claim(ClaimTypes.Name, ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier).Value));

            var claims = ClaimsRepository.GetClaims(principal, details);

            var dictionary = new Dictionary<string, string>();
            foreach (var claim in claims)
            {
                if (!dictionary.ContainsKey(claim.Type))
                {
                    dictionary.Add(claim.Type, claim.Value);
                }
                else
                {
                    var currentValue = dictionary[claim.Type];
                    dictionary[claim.Type] = currentValue += ("," + claim.Value);
                }
            }

            return Request.CreateResponse<Dictionary<string, string>>(HttpStatusCode.OK, dictionary, "application/json");
        }
    }
}