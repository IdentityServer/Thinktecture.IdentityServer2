/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Repositories
{
    /// <summary>
    /// Repository for emitting claims into an outgoing token and claims metadata
    /// </summary>
    public interface IClaimsRepository
    {
        IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails);
        IEnumerable<string> GetSupportedClaimTypes();
        IEnumerable<ProfileProperty> GetProfileProperties();
        IEnumerable<ProfileProperty> GetProfileProperties(string userName);
        void UpdateProfileProperties(string userName, ProfileProperty[] profileProperties);
    }

    public class ProfileProperty
    {
        public Type PropertyType { get; set; }
        public String Name { get; set; }
        public Object Value { get; set; }
    }
}
