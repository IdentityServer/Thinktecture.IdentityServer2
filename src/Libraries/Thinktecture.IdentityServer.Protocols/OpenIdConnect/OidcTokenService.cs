using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

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

        public OidcTokenResponse CreateTokenResponse(ValidatedRequest request)
        {
            var idToken = CreateIdentityToken(request.Grant.Subject, request.Grant.ClientId);

            if (request.Grant.GrantType == StoredGrantType.AuthorizationCode)
            {
                request.GrantsRepository.Delete(request.Grant.GrantId);
            }

            return new OidcTokenResponse
            {
                IdentityToken = idToken.ToJwtString(),
                TokenType = "Bearer",
                ExpiresIn = 60 * 60
            };
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

        public AccessToken CreateAccessToken(string subject, string audience, string clientId, IEnumerable<string> scopes)
        {
            return new AccessToken
            {
                Audience = audience,
                Subject = subject,
                ClientId = clientId,
                Scopes = scopes,

                Ttl = 60,
                Issuer = _issuer,
                SigningCredential = new X509SigningCredentials(_signingCert)
            };
        }
    }
}
