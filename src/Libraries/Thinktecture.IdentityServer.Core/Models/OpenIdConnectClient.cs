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
        [Display(Name="Client ID", Description="Unique identifier for the client.")]
        public string ClientId { get; set; }
        
        [Display(Name = "Client Secret", Description = "Password for the client.")]
        public string ClientSecret { get; set; }
        
        [ScaffoldColumn(false)]
        [UIHint("Enum")]
        public ClientSecretTypes ClientSecretType { get; set; }
        
        [Required]
        [Display(Name = "Name", Description = "Display name for the client.")]
        public string Name { get; set; }
        
        // openid connect
        [Display(Name = "Flow", Description = "OAuth2 flow for the client -- either server-side client (code) or naitve/javascript client (implicit).")]
        [UIHint("Enum")]
        public OpenIdConnectFlows Flow { get; set; }

        [Display(Name = "Access Token Lifetime", Description = "Lifetime (in minutes) of access token issued to client.")]
        public int AccessTokenLifetime { get; set; }

        [Display(Name = "Allow Refresh Token", Description = "Only allowed for code flow clients.")]
        public bool AllowRefreshToken { get; set; }

        [Display(Name = "Refresh Token Lifetime", Description = "Lifetime (in minutes) of refresh token issued to client. Only allowed for code flow clients.")]
        public int RefreshTokenLifetime { get; set; }

        [Display(Name = "Require Consent", Description = "For this client should user be prompted to grant consent to access the user's profile data.")]
        public bool RequireConsent { get; set; }

        [ScaffoldColumn(false)]
        public string[] RedirectUris { get; set; }
        
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            return Enumerable.Empty<ValidationResult>();
        }
    }
}