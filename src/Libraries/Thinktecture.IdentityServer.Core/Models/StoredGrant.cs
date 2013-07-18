using System;
using System.Collections.Generic;
using Thinktecture.IdentityModel.Constants;

namespace Thinktecture.IdentityServer.Models
{
    public class StoredGrant
    {
        public string GrantId { get; set; }
        public StoredGrantType GrantType { get; set; }
        
        public string Subject { get; set; }
        public string Scopes { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }

        public DateTime Created { get; set; }
        public DateTime Expiration { get; set; }
        public DateTime? RefreshTokenExpiration { get; set; }

        public StoredGrant()
        {
            GrantId = Guid.NewGuid().ToString("N");
        }

        public static StoredGrant CreateAuthorizationCode(string clientId, string subject, string scopes, string redirectUri, int ttl)
        {
            return new StoredGrant
            {
                GrantType = StoredGrantType.AuthorizationCode,
                
                ClientId = clientId,
                Subject = subject,
                Scopes = scopes,
                RedirectUri = redirectUri,
                Created = DateTime.UtcNow,
                Expiration = DateTime.UtcNow.AddMinutes(ttl)
            };
        }

        public static StoredGrant CreateRefreshToken(string clientId, string subject, string scopes, int ttl)
        {
            return new StoredGrant
            {
                GrantType = StoredGrantType.RefreshToken,

                ClientId = clientId,
                Subject = subject,
                Scopes = scopes,
                Created = DateTime.UtcNow,
                Expiration = DateTime.UtcNow.AddMinutes(ttl)
            };
        }
    }
}
