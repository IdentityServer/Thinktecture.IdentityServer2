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

        public virtual IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            var userName = principal.Identity.Name;
            var claims = new List<Claim>(from c in principal.Claims select c);

            // email address
            var membership = Membership.FindUsersByName(userName)[userName];
            if (membership != null)
            {
                string email = membership.Email;
                if (!String.IsNullOrEmpty(email))
                {
                    claims.Add(new Claim(ClaimTypes.Email, email));
                }
            }

            // roles
            GetRolesForToken(userName).ToList().ForEach(role => claims.Add(new Claim(ClaimTypes.Role, role)));

            // profile claims
            claims.AddRange(GetProfileClaims(userName));

            return claims;
        }

        protected virtual IEnumerable<Claim> GetProfileClaims(string userName)
        {
            var claims = new List<Claim>();

            if (ProfileManager.Enabled)
            {
                var profile = ProfileBase.Create(userName, true);
                if (profile != null)
                {
                    foreach (SettingsProperty prop in ProfileBase.Properties)
                    {
                        object value = profile.GetPropertyValue(prop.Name);
                        if (value != null)
                        {
                            if (!string.IsNullOrWhiteSpace(value.ToString()))
                            {
                                claims.Add(new Claim(GetProfileClaimType(prop.Name.ToLowerInvariant()), value.ToString()));
                            }
                        }
                    }
                }
            }

            return claims;
        }

        public virtual IEnumerable<ProfileProperty> GetProfileProperties(string userName)
        {
            var properties = new List<ProfileProperty>();

            if (ProfileManager.Enabled)
            {
                var profile = ProfileBase.Create(userName, true);
                if (profile != null)
                {
                    foreach (SettingsProperty prop in ProfileBase.Properties)
                    {
                        object value = profile.GetPropertyValue(prop.Name);
                        properties.Add(new ProfileProperty() { Name = prop.Name, PropertyType = prop.PropertyType, Value = value });
                    }
                }
            }

            return properties;
        }

        public void UpdateProfileProperties(string userName, ProfileProperty[] profileProperties)
        {
            if (profileProperties.All(x => String.IsNullOrWhiteSpace(Convert.ToString(x.Value))))
            {
                ProfileManager.DeleteProfile(userName);
            }

            var profile = ProfileBase.Create(userName);
            for (int i = 0; i < profileProperties.Length; i++)
            {
                var prop = ProfileBase.Properties[profileProperties[i].Name];
                if (prop != null && !(String.IsNullOrWhiteSpace(Convert.ToString(profileProperties[i].Value)) && prop.PropertyType.IsValueType))
                {
                    object val = Convert.ChangeType(profileProperties[i].Value, prop.PropertyType);
                    profile.SetPropertyValue(prop.Name, val);
                }
            }

            profile.Save();
        }

        public virtual IEnumerable<ProfileProperty> GetProfileProperties()
        {
            var properties = new List<ProfileProperty>();

            if (ProfileManager.Enabled)
            {
                foreach (SettingsProperty prop in ProfileBase.Properties)
                {
                    properties.Add(new ProfileProperty() { Name = prop.Name, PropertyType = prop.PropertyType });
                }
            }

            return properties;
        }

        protected virtual string GetProfileClaimType(string propertyName)
        {
            if (StandardClaimTypes.Mappings.ContainsKey(propertyName))
            {
                return StandardClaimTypes.Mappings[propertyName];
            }
            else
            {
                return string.Format("{0}{1}", ProfileClaimPrefix, propertyName);
            }
        }

        public virtual IEnumerable<string> GetSupportedClaimTypes()
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
                    claimTypes.Add(GetProfileClaimType(prop.Name.ToLowerInvariant()));
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