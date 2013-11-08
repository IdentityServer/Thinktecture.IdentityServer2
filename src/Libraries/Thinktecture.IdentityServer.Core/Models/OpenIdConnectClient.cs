/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System;

namespace Thinktecture.IdentityServer.Models
{
    public class OpenIdConnectClient : IValidatableObject
    {
        // general
        [Required]
        [ScaffoldColumn(false)]
        [Display(ResourceType = typeof (Resources.Models.Configuration.OpenIdConnectClient), Name = "ClientId", Description = "ClientIdDescription")]
        public string ClientId { get; set; }
        
        [Display(ResourceType = typeof(Resources.Models.Configuration.OpenIdConnectClient), Name = "ClientSecret", Description = "ClientSecretDescription")]
        public string ClientSecret { get; set; }
        
        [ScaffoldColumn(false)]
        [UIHint("Enum")]
        public ClientSecretTypes ClientSecretType { get; set; }
        
        [Required]
        [Display(ResourceType = typeof(Resources.Models.Configuration.OpenIdConnectClient), Name = "Name", Description = "NameDescription")]
        public string Name { get; set; }
        
        // openid connect
        [Display(ResourceType = typeof(Resources.Models.Configuration.OpenIdConnectClient), Name = "Flow", Description = "FlowDescription")]
        [UIHint("Enum")]
        public OpenIdConnectFlows Flow { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.OpenIdConnectClient), Name = "AccessTokenLifetime", Description = "AccessTokenLifetimeDescription")]
        public int AccessTokenLifetime { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.OpenIdConnectClient), Name = "AllowRefreshToken", Description = "AllowRefreshTokenDescription")]
        public bool AllowRefreshToken { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.OpenIdConnectClient), Name = "RefreshTokenLifetime", Description = "RefreshTokenLifetimeDescription")]
        public int RefreshTokenLifetime { get; set; }

        [Display(ResourceType = typeof(Resources.Models.Configuration.OpenIdConnectClient), Name = "RequireConsent", Description = "RequireConsentDescription")]
        public bool RequireConsent { get; set; }

        [ScaffoldColumn(false)]
        public string[] RedirectUris { get; set; }
        
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            return Enumerable.Empty<ValidationResult>();
        }
    }
}