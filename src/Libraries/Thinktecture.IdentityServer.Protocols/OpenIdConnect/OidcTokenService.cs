using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Thinktecture.IdentityServer.Models;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    class OidcTokenService
    {
        string _issuer;
        X509Certificate2 _signingCert;

        public OidcTokenService(string issuer, X509Certificate2 signingCertificate)
        {
            _issuer = issuer;
            _signingCert = signingCertificate;
        }

        public OidcTokenResponse CreateTokenResponse(StoredGrant grant)
        {
            var accessToken = CreateAccessToken(grant.Subject, _issuer + "/userinfo", grant.ClientId, grant.Scopes);
            var response = new OidcTokenResponse
            {
                AccessToken = accessToken.ToJwtString(),
                TokenType = "Bearer",
                ExpiresIn = 60 * 60
            };

            if (grant.GrantType == StoredGrantType.AuthorizationCode)
            {
                var idToken = CreateIdentityToken(grant.Subject, grant.ClientId);
                response.IdentityToken = idToken.ToJwtString();
            }

            return response;
        }

        public IdentityToken CreateIdentityToken(string subject, string audience)
        {
            return new IdentityToken
            {
                Audience = audience,
                Subject = subject,

                Ttl = 60,
                Issuer = _issuer,
                SigningCredential = new X509SigningCredentials(_signingCert)
            };
        }

        public AccessToken CreateAccessToken(string subject, string audience, string clientId, string scopes)
        {
            var splitScopes = scopes.Split(' ');

            return new AccessToken
            {
                Audience = audience,
                Subject = subject,
                ClientId = clientId,
                Scopes = splitScopes,

                Ttl = 60,
                Issuer = _issuer,
                SigningCredential = new X509SigningCredentials(_signingCert)
            };
        }
    }
}
