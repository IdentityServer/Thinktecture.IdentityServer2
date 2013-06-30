/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.Collections.Generic;

namespace Thinktecture.IdentityServer.Protocols.OpenIdConnect
{
    public static class OidcConstants
    {
        static Dictionary<string, IEnumerable<string>> _dictionary = new Dictionary<string, IEnumerable<string>>
        {
            { Scopes.Profile, new string[]
                            { 
                                ClaimTypes.Name,
                                ClaimTypes.FamilyName,
                                ClaimTypes.GivenName,
                                ClaimTypes.MiddleName,
                                ClaimTypes.NickName,
                                ClaimTypes.PreferredUserName,
                                ClaimTypes.Profile,
                                ClaimTypes.Picture,
                                ClaimTypes.WebSite,
                                ClaimTypes.Gender,
                                ClaimTypes.BirthDate,
                                ClaimTypes.ZoneInfo,
                                ClaimTypes.Locale,
                                ClaimTypes.UpdatedAt 
                            }},
            { Scopes.Email, new string[]
                            { 
                                ClaimTypes.Email,
                                ClaimTypes.EmailVerified 
                            }},
            { Scopes.Address, new string[]
                            {
                                ClaimTypes.Address
                            }},
            { Scopes.Phone, new string[]
                            {
                                ClaimTypes.PhoneNumber,
                                ClaimTypes.PhoneNumberVerified
                            }},
        };

        public static Dictionary<string, IEnumerable<string>> Mappings 
        {
            get { return _dictionary; } 
        }

        public static class Scopes
        {
            public const string OpenId        = "openid";
            public const string Profile       = "profile";
            public const string Email         = "email";
            public const string Address       = "address";
            public const string Phone         = "phone";
            public const string OfflineAccess = "offline_access";
        }

        public static class ClaimTypes
        {
            public const string Subject             = "sub";
            public const string Name                = "name";
            public const string GivenName           = "given_name";
            public const string FamilyName          = "family_name";
            public const string MiddleName          = "middle_name";
            public const string NickName            = "nickname";
            public const string PreferredUserName   = "preferred_username";
            public const string Profile             = "profile";
            public const string Picture             = "picture";
            public const string WebSite             = "website";
            public const string Email               = "email";
            public const string EmailVerified       = "email_verified";
            public const string Gender              = "gender";
            public const string BirthDate           = "birthdate";
            public const string ZoneInfo            = "zoneinfo";
            public const string Locale              = "locale";
            public const string PhoneNumber         = "phone_number";
            public const string PhoneNumberVerified = "phone_number_verified";
            public const string Address             = "address";
            public const string UpdatedAt           = "updated_at";
        }
    }
}
