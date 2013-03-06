/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Protocols.OAuth2
{
    public class TokenRequest
    {
        [Required]
        [JsonProperty(PropertyName = "grant_type")]
        public string Grant_Type { get; set; }

        [JsonProperty(PropertyName = "scope")]
        public string Scope { get; set; }

        [JsonProperty(PropertyName = "username")]
        public string UserName { get; set; }

        [JsonProperty(PropertyName = "password")]
        public string Password { get; set; }
    }
}