/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class OAuth2Configuration : ProtocolConfiguration
    {
        [Display(Name = "Enable Implicit Flow", Description = "This flow is for native apps and client web applications.")]
        public bool EnableImplicitFlow { get; set; }

        [Display(Name = "Enable Resource Owner Flow", Description = "This flow is for trusted applications only. Users enter their credentials directly into the client.")]
        public bool EnableResourceOwnerFlow { get; set; }

        [Display(Name = "Enable Consent Page", Description = "Specifies whether a consent page is shown before a token/code is returned.")]
        public bool EnableConsent { get; set; }
    }
}
