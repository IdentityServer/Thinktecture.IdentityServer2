/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class OAuth2Configuration : ProtocolConfiguration
    {
        [Display(ResourceType = typeof (Resources.Models.Configuration.OAuth2Configuration), Name = "EnableImplicitFlow", Description = "EnableImplicitFlowDescription")]
        public bool EnableImplicitFlow { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.OAuth2Configuration), Name = "EnableResourceOwnerFlow", Description = "EnableResourceOwnerFlowDescription")]
        public bool EnableResourceOwnerFlow { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.OAuth2Configuration), Name = "EnableCodeFlow", Description = "EnableCodeFlowDescription")]
        public bool EnableCodeFlow { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.OAuth2Configuration), Name = "EnableConsent", Description = "EnableConsentDescription")]
        public bool EnableConsent { get; set; }
    }
}
