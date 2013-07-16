/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using Newtonsoft.Json;

namespace Thinktecture.IdentityServer.Protocols.OAuth2
{
    [JsonObject]
    public class TokenRequest
    {
        [JsonProperty(PropertyName = "grant_type")]
        public string Grant_Type { get; set; }

        [JsonProperty(PropertyName = "scope")]
        public string Scope { get; set; }

        [JsonProperty(PropertyName = "username")]
        public string UserName { get; set; }

        [JsonProperty(PropertyName = "password")]
        public string Password { get; set; }

        [JsonProperty(PropertyName = "code")]
        public string Code { get; set; }

        [JsonProperty(PropertyName = "redirect_uri")]
        public string Redirect_Uri { get; set; }

        [JsonProperty(PropertyName = "refresh_token")]
        public string Refresh_Token { get; set; }

        [JsonProperty(PropertyName = "assertion")]
        public string Assertion { get; set; }
    }
}