/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class FederationMetadataConfiguration : ProtocolConfiguration
    {
        [UIHint("Enum")]
        [Display(ResourceType = typeof(Resources.Models.Configuration.FederationMetadataConfiguration), Name = "PrimaryPassiveEndpoint", Description = "PrimaryPassiveEndpointDescription")]
        public PassiveEndpoints? PrimaryPassiveEndpoint { get; set; }
    }
}
