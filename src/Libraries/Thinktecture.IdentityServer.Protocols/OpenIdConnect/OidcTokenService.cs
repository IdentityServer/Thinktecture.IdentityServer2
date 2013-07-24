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

        public OidcTokenResponse CreateTokenResponse(StoredGrant grant, int accessTokenLifetime)
        {
            var accessToken = CreateAccessToken(grant.Subject, _issuer + "/userinfo", grant.ClientId, grant.Scopes, accessTokenLifetime);
            var response = new OidcTokenResponse
            {
                AccessToken = accessToken.ToJwtString(),
                TokenType = "Bearer",
                ExpiresIn = accessTokenLifetime * 60
            };

            if (grant.GrantType == StoredGrantType.AuthorizationCode)
            {
                var idToken = CreateIdentityToken(grant.Subject, grant.ClientId, 60);
                response.IdentityToken = idToken.ToJwtString();
            }

            return response;
        }

        public IdentityToken CreateIdentityToken(string subject, string audience, int ttl)
        {
            return new IdentityToken
            {
                Audience = audience,
                Subject = subject,

                Ttl = ttl,
                Issuer = _issuer,
                SigningCredential = new X509SigningCredentials(_signingCert)
            };
        }

        public AccessToken CreateAccessToken(string subject, string audience, string clientId, string scopes, int ttl)
        {
            var splitScopes = scopes.Split(' ');

            return new AccessToken
            {
                Audience = audience,
                Subject = subject,
                ClientId = clientId,
                Scopes = splitScopes,

                Ttl = ttl,
                Issuer = _issuer,
                SigningCredential = new X509SigningCredentials(_signingCert)
            };
        }
    }
}
