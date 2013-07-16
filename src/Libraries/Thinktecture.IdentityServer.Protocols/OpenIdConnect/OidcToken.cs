using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    public abstract class OidcToken
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int Ttl { get; set; }
        public List<Claim> ExtraClaims { get; set; }
        public X509SigningCredentials SigningCredential { get; set; }

        protected virtual List<Claim> CreateClaims()
        {
            var claims = new List<Claim>();

            if (ExtraClaims != null)
            {
                claims.AddRange(ExtraClaims);
            }

            return claims;
        }

        public virtual JwtSecurityToken ToJwt()
        {
            if (string.IsNullOrWhiteSpace(Issuer))
            {
                throw new InvalidOperationException("Issuer is empty");
            }
            if (string.IsNullOrWhiteSpace(Audience))
            {
                throw new InvalidOperationException("Audience is empty");
            }
            if (SigningCredential == null)
            {
                throw new InvalidOperationException("Signing credential is empty");
            }
            if (Ttl == 0)
            {
                throw new InvalidOperationException("Ttl is 0");
            }

            var claims = CreateClaims();

            return new JwtSecurityToken(
                Issuer,
                Audience,
                claims,
                new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(Ttl)),
                SigningCredential);

        }

        public virtual string ToJwtString()
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(ToJwt());
        }
    }
}