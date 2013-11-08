/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class AdfsIntegrationConfiguration : ProtocolConfiguration, IValidatableObject
    {
        // general settings - authentication

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "UsernameAuthenticationEnabled", Description = "UsernameAuthenticationEnabledDescription")]
        public bool UsernameAuthenticationEnabled { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "SamlAuthenticationEnabled", Description = "SamlAuthenticationEnabledDescription")]
        public bool SamlAuthenticationEnabled { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "JwtAuthenticationEnabled", Description = "JwtAuthenticationEnabledDescription")]
        public bool JwtAuthenticationEnabled { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "PassThruAuthenticationToken", Description = "PassThruAuthenticationTokenDescription")]
        public bool PassThruAuthenticationToken { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "AuthenticationTokenLifetime", Description = "AuthenticationTokenLifetimeDescription")]
        [Range(0, Int32.MaxValue, ErrorMessageResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), ErrorMessageResourceName = "AuthenticationTokenLifetimeRangeErrorMessage")]
        public int AuthenticationTokenLifetime { get; set; }

        // adfs settings

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "UserNameAuthenticationEndpoint", Description = "UserNameAuthenticationEndpointDescription")]
        public string UserNameAuthenticationEndpoint { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "FederationEndpoint", Description = "FederationEndpointDescription")]
        public string FederationEndpoint { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "IssuerUri", Description = "IssuerUriDescription")]
        public string IssuerUri { get; set; }

        string _IssuerThumbprint;
        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "IssuerThumbprint", Description = "IssuerThumbprintDescription")]
        public string IssuerThumbprint
        {
            get
            {
                return _IssuerThumbprint;
            }
            set
            {
                _IssuerThumbprint = value;
                if (_IssuerThumbprint != null) _IssuerThumbprint = _IssuerThumbprint.Replace(" ", "");
            }
        }

        [Display(ResourceType = typeof(Resources.Models.Configuration.AdfsIntegrationConfiguration), Name = "EncryptionCertificate", Description = "EncryptionCertificateDescription")]
        public X509Certificate2 EncryptionCertificate { get; set; }

        public System.Collections.Generic.IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            // common stuff
            if (this.Enabled)
            {
                if (this.UsernameAuthenticationEnabled ||
                    this.SamlAuthenticationEnabled ||
                    this.JwtAuthenticationEnabled)
                {
                    if (!this.PassThruAuthenticationToken &&
                        String.IsNullOrWhiteSpace(this.IssuerThumbprint))
                    {
                        yield return new ValidationResult(Resources.Models.Configuration.AdfsIntegrationConfiguration.PassThruAuthenticationTokenRequiresIssuerThumbprintErrorMessage, new[] { "IssuerThumbprint" });
                    }
                }

                if (this.UsernameAuthenticationEnabled)
                {
                    if (String.IsNullOrWhiteSpace(this.UserNameAuthenticationEndpoint))
                    {
                        yield return new ValidationResult(Resources.Models.Configuration.AdfsIntegrationConfiguration.UserNameAuthenticationEnabledRequiresUserNameAuthenticationEndpointErrorMessage, new[] { "UserNameAuthenticationEndpoint" });
                    }
                }

                if (this.SamlAuthenticationEnabled)
                {
                    if (String.IsNullOrWhiteSpace(this.IssuerThumbprint))
                    {
                        yield return new ValidationResult(Resources.Models.Configuration.AdfsIntegrationConfiguration.SamlAuthenticationEnabledRequiresIssuerThumbprintErrorMessage, new[] { "IssuerThumbprint" });
                    }

                    // EncryptionCertificate check done in controller

                    if (String.IsNullOrWhiteSpace(this.IssuerUri))
                    {
                        yield return new ValidationResult(Resources.Models.Configuration.AdfsIntegrationConfiguration.SamlAuthenticationEnabledRequiresIssuerUriErrorMessage, new[] { "IssuerUri" });
                    }
                    if (String.IsNullOrWhiteSpace(this.FederationEndpoint))
                    {
                        yield return new ValidationResult(Resources.Models.Configuration.AdfsIntegrationConfiguration.SamlAuthenticationEnabledRequiresFederationEndpointErrorMessage, new[] { "FederationEndpoint" });
                    }
                }

                if (this.JwtAuthenticationEnabled)
                {
                    // EncryptionCertificate check done in controller

                    if (String.IsNullOrWhiteSpace(this.IssuerUri))
                    {
                        yield return new ValidationResult(Resources.Models.Configuration.AdfsIntegrationConfiguration.JwtAuthenticationEnabledRequiresIssuerUriErrorMessage, new[] { "IssuerUri" });
                    }
                    if (String.IsNullOrWhiteSpace(this.FederationEndpoint))
                    {
                        yield return new ValidationResult(Resources.Models.Configuration.AdfsIntegrationConfiguration.JwtAuthenticationEnabledRequiresFederationEndpointErrorMessage, new[] { "FederationEndpoint" });
                    }
                }
            }
        }
    }
}
