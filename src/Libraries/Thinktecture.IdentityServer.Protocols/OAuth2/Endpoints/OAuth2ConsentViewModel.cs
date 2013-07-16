/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

namespace Thinktecture.IdentityServer.Protocols.OAuth2
{
    public class OAuth2ConsentViewModel
    {
        public string ResourceName { get; set; }
        public string ResourceUri { get; set; }
        public string ClientName { get; set; }
        public bool RefreshTokenEnabled { get; set; }
    }
}
