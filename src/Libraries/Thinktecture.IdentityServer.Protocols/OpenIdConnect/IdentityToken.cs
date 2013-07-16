using System;
using System.Collections.Generic;
using System.Security.Claims;
using Thinktecture.IdentityModel.Extensions;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    public class IdentityToken : OidcToken
    {
        public string Subject { get; set; }

        protected override List<Claim> CreateClaims()
        {
            if (string.IsNullOrWhiteSpace(Subject))
            {
                throw new InvalidOperationException("Subject is empty");
            }

            var claims = base.CreateClaims();
            claims.Add(new Claim(OidcConstants.ClaimTypes.Subject, Subject));
            claims.Add(new Claim("iat", DateTime.UtcNow.ToEpochTime().ToString()));
            
            return claims;
        }
    }
}