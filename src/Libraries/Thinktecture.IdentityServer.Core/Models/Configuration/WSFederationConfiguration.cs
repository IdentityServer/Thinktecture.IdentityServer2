/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class WSFederationConfiguration : ProtocolConfiguration
    {
        [Display(ResourceType = typeof (Resources.Models.Configuration.WSFederationConfiguration), Name = "EnableAuthentication", Description = "EnableAuthenticationDescription")]
        public bool EnableAuthentication { get; set; }
        
        [Display(ResourceType = typeof (Resources.Models.Configuration.WSFederationConfiguration), Name = "EnableFederation", Description = "EnableFederationDescription")]
        public bool EnableFederation { get; set; }
        
        [Display(ResourceType = typeof (Resources.Models.Configuration.WSFederationConfiguration), Name = "EnableHrd", Description = "EnableHrdDescription")]
        public bool EnableHrd { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.WSFederationConfiguration), Name = "AllowReplyTo", Description = "AllowReplyToDescription")]
        public bool AllowReplyTo { get; set; }
        
        [Display(ResourceType = typeof (Resources.Models.Configuration.WSFederationConfiguration), Name = "RequireReplyToWithinRealm", Description = "RequireReplyToWithinRealmDescription")]
        public Boolean RequireReplyToWithinRealm { get; set; }
        
        [Display(ResourceType = typeof (Resources.Models.Configuration.WSFederationConfiguration), Name = "RequireSslForReplyTo", Description = "RequireSslForReplyToDescription")]
        public Boolean RequireSslForReplyTo { get; set; }
    }
}
