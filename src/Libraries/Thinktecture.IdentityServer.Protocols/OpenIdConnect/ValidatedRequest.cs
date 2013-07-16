using System.Collections.Generic;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    public class ValidatedRequest
    {
        public Client Client { get; set; }

        public string State { get; set; }

        public string RedirectUri { get; set; }

        public string ResponseType { get; set; }

        public string Scopes { get; set; }

        public string GrantType { get; set; }

        public string AuthorizationCode { get; set; }

        public IStoredGrantRepository GrantsRepository { get; set; }

        public StoredGrant Grant { get; set; }
    }
}
