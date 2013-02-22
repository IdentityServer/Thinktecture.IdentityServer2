/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class ProtocolConfiguration
    {
        [Display(Order=1, ResourceType = typeof (Resources.Models.Configuration.ProtocolConfiguration), Name = "Enabled", Description = "EnabledDescription")]
        public bool Enabled { get; set; }
    }
}
