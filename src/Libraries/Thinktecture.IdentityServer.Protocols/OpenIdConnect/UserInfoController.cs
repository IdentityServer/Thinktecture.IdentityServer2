/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.IdentityModel.Protocols.WSTrust;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Thinktecture.IdentityModel.Constants;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    [Authorize]
    public class UserInfoController : ApiController
    {
        HttpResponseMessage Get()
        {
            var requestClaims = new RequestClaimCollection();

            var scopes = ClaimsPrincipal.Current.FindAll(OAuth2Constants.Scope);
            foreach (var scope in scopes)
            {
                if (OidcConstants.Mappings.ContainsKey(scope.Value))
                {
                    foreach (var oidcClaim in OidcConstants.Mappings[scope.Value])
                    {
                        requestClaims.Add(new RequestClaim(oidcClaim));
                    }
                }
                else
                {
                    Request.CreateErrorResponse(HttpStatusCode.BadRequest, "invalid scope");
                }
            }

            // populate RequestDetails
            // call ClaimsRepository

            // return response;

            throw new NotImplementedException();
        }
    }
}
