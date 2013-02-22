/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class GlobalConfiguration
    {
        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "SiteName", Description = "SiteNameDescription")]
        [Required]
        public String SiteName { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "IssuerUri", Description = "IssuerUriDescription")]
        [Required]
        public String IssuerUri { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "IssuerContactEmail", Description = "IssuerContactEmailDescription")]
        //[RegularExpression(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]\b", ErrorMessage = "{0} must be in the form of an email address.")]
        [Required]
        public String IssuerContactEmail { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "DefaultWSTokenType", Description = "DefaultWSTokenTypeDescription")]
        [Required]
        public string DefaultWSTokenType { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.GlobalConfiguration), Name = "DefaultHttpTokenType", Description = "DefaultHttpTokenTypeDescription")]
        [Required]
        public string DefaultHttpTokenType { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "DefaultTokenLifetime", Description = "DefaultTokenLifetimeDescription")]
        [Range(0, Int32.MaxValue)]
        public int DefaultTokenLifetime { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "MaximumTokenLifetime", Description = "MaximumTokenLifetimeDescription")]
        [Range(0, Int32.MaxValue)]
        public int MaximumTokenLifetime { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "SsoCookieLifetime", Description = "SsoCookieLifetimeDescription")]
        [Range(0, Int32.MaxValue)]
        public int SsoCookieLifetime { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "RequireEncryption", Description = "RequireEncryptionDescription")]
        public Boolean RequireEncryption { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "RequireRelyingPartyRegistration", Description = "RequireRelyingPartyRegistrationDescription")]
        public Boolean RequireRelyingPartyRegistration { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "EnableClientCertificateAuthentication", Description = "EnableClientCertificateAuthenticationDescription")]
        public Boolean EnableClientCertificateAuthentication { get; set; }

        // TODO : Name = "Only Users in the '" + Constants.Roles.IdentityServerUsers + "' role can request tokens"
        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "EnforceUsersGroupMembership", Description = "EnforceUsersGroupMembershipDescription")]
        public Boolean EnforceUsersGroupMembership { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "HttpPort", Description = "HttpPortDescription")]
        [Range(0, Int32.MaxValue)]
        public int HttpPort { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.GlobalConfiguration), Name = "HttpsPort", Description = "HttpsPortDescription")]
        [Range(0, Int32.MaxValue)]
        public int HttpsPort { get; set; }
    }
}
