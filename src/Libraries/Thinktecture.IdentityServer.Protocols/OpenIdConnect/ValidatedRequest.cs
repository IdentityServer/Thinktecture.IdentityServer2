﻿using System.Collections.Generic;
using Thinktecture.IdentityServer.Models;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    public class ValidatedRequest
    {
        public Client Client { get; set; }

        public string State { get; set; }

        public string RedirectUri { get; set; }

        public string ResponseType { get; set; }

        public IEnumerable<string> Scopes { get; set; }

        public string GrantType { get; set; }
    }
}