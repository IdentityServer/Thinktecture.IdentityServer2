/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web.Profile;
using System.Web.Security;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Repositories
{
    public class ProviderClaimsRepository : IClaimsRepository
    {
        private const string ProfileClaimPrefix = "http://identityserver.thinktecture.com/claims/profileclaims/";

        public IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            var userName = principal.Identity.Name;
            var claims = new List<Claim>(from c in principal.Claims select c);

            // email address
            string email = Membership.FindUsersByName(userName)[userName].Email;
            if (!String.IsNullOrEmpty(email))
            {
                claims.Add(new Claim(ClaimTypes.Email, email));
            }

            // roles
            GetRolesForToken(userName).ToList().ForEach(role => claims.Add(new Claim(ClaimTypes.Role, role)));

            // profile claims
            if (ProfileManager.Enabled)
            {
                var profile = ProfileBase.Create(userName, true);
                if (profile != null)
                {
                    foreach (SettingsProperty prop in ProfileBase.Properties)
                    {
                        string value = profile.GetPropertyValue(prop.Name).ToString();
                        if (!String.IsNullOrWhiteSpace(value))
                        {
                            claims.Add(new Claim(ProfileClaimPrefix + prop.Name.ToLowerInvariant(), value));
                        }
                    }
                }
            }

            return claims;
        }

        public IEnumerable<string> GetSupportedClaimTypes()
        {
            var claimTypes = new List<string>
            {
                ClaimTypes.Name,
                ClaimTypes.Email,
                ClaimTypes.Role
            };

            if (ProfileManager.Enabled)
            {
                foreach (SettingsProperty prop in ProfileBase.Properties)
                {
                    claimTypes.Add(ProfileClaimPrefix + prop.Name.ToLowerInvariant());
                }
            }

            return claimTypes;
        }

        protected virtual IEnumerable<string> GetRolesForToken(string userName)
        {
            var returnedRoles = new List<string>();

            if (Roles.Enabled)
            {
                var roles = Roles.GetRolesForUser(userName);
                returnedRoles = roles.Where(role => !(role.StartsWith(Constants.Roles.InternalRolesPrefix))).ToList();
            }

            return returnedRoles;
        }
    }
}