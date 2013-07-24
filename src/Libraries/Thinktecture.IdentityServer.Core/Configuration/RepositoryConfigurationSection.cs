/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

namespace Thinktecture.IdentityServer.Configuration
{
    /// <summary>
    /// The StarterTokenServiceSection Configuration Section.
    /// </summary>
    public partial class RepositoryConfigurationSection : global::System.Configuration.ConfigurationSection
    {
        public const string SectionName = "thinktecture.identityServer.repositories";

        #region TokenServiceConfiguration Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String TokenServiceConfigurationPropertyName = "tokenServiceConfiguration";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(TokenServiceConfigurationPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.ConfigurationRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String TokenServiceConfiguration
        {
            get
            {
                return (global::System.String)base[TokenServiceConfigurationPropertyName];
            }
            set
            {
                base[TokenServiceConfigurationPropertyName] = value;
            }
        }

        #endregion

        #region UserManagement Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String UserManagementPropertyName = "userManagement";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(UserManagementPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.ProviderUserManagementRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String UserManagement
        {
            get
            {
                return (global::System.String)base[UserManagementPropertyName];
            }
            set
            {
                base[UserManagementPropertyName] = value;
            }
        }

        #endregion

        #region UserValidation Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String UserValidationPropertyName = "userValidation";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(UserValidationPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.ProviderUserRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String UserValidation
        {
            get
            {
                return (global::System.String)base[UserValidationPropertyName];
            }
            set
            {
                base[UserValidationPropertyName] = value;
            }
        }

        #endregion

        #region ClaimsRepository Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String ClaimsRepositoryPropertyName = "claimsRepository";

        [global::System.Configuration.ConfigurationProperty(ClaimsRepositoryPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.ProviderClaimsRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String ClaimsRepository
        {
            get
            {
                return (global::System.String)base[ClaimsRepositoryPropertyName];
            }
            set
            {
                base[ClaimsRepositoryPropertyName] = value;
            }
        }

        #endregion

        #region ClaimsTransformationRulesRepository Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String ClaimsTransformationRulesRepositoryPropertyName = "claimsTransformationRules";

        [global::System.Configuration.ConfigurationProperty(ClaimsTransformationRulesRepositoryPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.PassThruTransformationRuleRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String ClaimsTransformationRules
        {
            get
            {
                return (global::System.String)base[ClaimsTransformationRulesRepositoryPropertyName];
            }
            set
            {
                base[ClaimsTransformationRulesRepositoryPropertyName] = value;
            }
        }

        #endregion

        #region RelyingParties Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String RelyingPartiesPropertyName = "relyingParties";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(RelyingPartiesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.RelyingPartyRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String RelyingParties
        {
            get
            {
                return (global::System.String)base[RelyingPartiesPropertyName];
            }
            set
            {
                base[RelyingPartiesPropertyName] = value;
            }
        }

        #endregion

        #region ClientCertificates Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String ClientCertificatesPropertyName = "clientCertificates";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(ClientCertificatesPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.ClientCertificatesRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String ClientCertificates
        {
            get
            {
                return (global::System.String)base[ClientCertificatesPropertyName];
            }
            set
            {
                base[ClientCertificatesPropertyName] = value;
            }
        }

        #endregion

        #region ClientsRepository Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String ClientsRepositoryPropertyName = "clientsRepository";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(ClientsRepositoryPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.ClientCertificatesRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String ClientsRepository
        {
            get
            {
                return (global::System.String)base[ClientsRepositoryPropertyName];
            }
            set
            {
                base[ClientsRepositoryPropertyName] = value;
            }
        }

        #endregion

        #region OpenIdConnectClientsRepository Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String OpenIdConnectClientsRepositoryPropertyName = "openIdConnectClientsRepository";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(OpenIdConnectClientsRepositoryPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.OpenIdConnectClientsRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String OpenIdConnectClientsRepository
        {
            get
            {
                return (global::System.String)base[OpenIdConnectClientsRepositoryPropertyName];
            }
            set
            {
                base[OpenIdConnectClientsRepositoryPropertyName] = value;
            }
        }

        #endregion

        #region CodeTokenRepository Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String CodeTokenRepositoryPropertyName = "codeTokenRepository";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(CodeTokenRepositoryPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.RefreshTokenRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String CodeTokenRepository
        {
            get
            {
                return (global::System.String)base[CodeTokenRepositoryPropertyName];
            }
            set
            {
                base[CodeTokenRepositoryPropertyName] = value;
            }
        }

        #endregion

        #region StoredGrantRepository Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String StoredGrantRepositoryPropertyName = "storedGrantRepository";

        [global::System.Configuration.ConfigurationProperty(StoredGrantRepositoryPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.StoredGrantRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String StoredGrantRepository
        {
            get
            {
                return (global::System.String)base[StoredGrantRepositoryPropertyName];
            }
            set
            {
                base[StoredGrantRepositoryPropertyName] = value;
            }
        }

        #endregion

        #region IdentityProvider Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String IdentityProviderPropertyName = "identityProvider";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(IdentityProviderPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.IdentityProviderRepository, Thinktecture.IdentityServer")]
        public global::System.String IdentityProvider
        {
            get
            {
                return (global::System.String)base[IdentityProviderPropertyName];
            }
            set
            {
                base[IdentityProviderPropertyName] = value;
            }
        }

        #endregion

        #region Delegation Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String DelegationPropertyName = "delegation";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(DelegationPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.Sql.DelegationRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String Delegation
        {
            get
            {
                return (global::System.String)base[DelegationPropertyName];
            }
            set
            {
                base[DelegationPropertyName] = value;
            }
        }

        #endregion

        #region Caching Property

        /// <summary>
        /// The XML name of the <see cref="ConfigurationProvider"/> property.
        /// </summary>
        internal const global::System.String CachingPropertyName = "caching";

        /// <summary>
        /// Gets or sets type of the class that provides encryption certificates
        /// </summary>
        [global::System.Configuration.ConfigurationProperty(CachingPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false, DefaultValue = "Thinktecture.IdentityServer.Repositories.MemoryCacheRepository, Thinktecture.IdentityServer.Core.Repositories")]
        public global::System.String Caching
        {
            get
            {
                return (global::System.String)base[CachingPropertyName];
            }
            set
            {
                base[CachingPropertyName] = value;
            }
        }

        #endregion

        #region Xmlns Property

        /// <summary>
        /// The XML name of the <see cref="Xmlns"/> property.
        /// </summary>
        internal const global::System.String XmlnsPropertyName = "xmlns";

        /// <summary>
        /// Gets the XML namespace of this Configuration Section.
        /// </summary>
        /// <remarks>
        /// This property makes sure that if the configuration file contains the XML namespace,
        /// the parser doesn't throw an exception because it encounters the unknown "xmlns" attribute.
        /// </remarks>
        [global::System.Configuration.ConfigurationProperty(XmlnsPropertyName, IsRequired = false, IsKey = false, IsDefaultCollection = false)]
        public global::System.String Xmlns
        {
            get
            {
                return (global::System.String)base[XmlnsPropertyName];
            }
        }

        #endregion
    }
}

