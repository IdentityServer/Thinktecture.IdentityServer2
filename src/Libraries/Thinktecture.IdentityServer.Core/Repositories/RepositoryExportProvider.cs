/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.Composition.Hosting;
using System.ComponentModel.Composition.Primitives;
using System.Configuration;
using Thinktecture.IdentityServer.Configuration;

namespace Thinktecture.IdentityServer.Repositories
{
    public class RepositoryExportProvider : ExportProvider
    {
        private Dictionary<string, string> _mappings;

        public RepositoryExportProvider()
        {
            var section = ConfigurationManager.GetSection(RepositoryConfigurationSection.SectionName) as RepositoryConfigurationSection;

            _mappings = new Dictionary<string, string>
            {
                { typeof(IConfigurationRepository).FullName, section.TokenServiceConfiguration },
                { typeof(IUserRepository).FullName, section.UserValidation },
                { typeof(IUserManagementRepository).FullName, section.UserManagement },
                { typeof(IClaimsRepository).FullName, section.ClaimsRepository },
                { typeof(IRelyingPartyRepository).FullName, section.RelyingParties },
                { typeof(IClientCertificatesRepository).FullName, section.ClientCertificates},
                { typeof(IDelegationRepository).FullName, section.Delegation},
                { typeof(ICacheRepository).FullName, section.Caching },
                { typeof(IIdentityProviderRepository).FullName, section.IdentityProvider },
                { typeof(IClaimsTransformationRulesRepository).FullName, section.ClaimsTransformationRules },
                { typeof(IClientsRepository).FullName, section.ClientsRepository },
                { typeof(ICodeTokenRepository).FullName, section.CodeTokenRepository },
                { typeof(IOpenIdConnectClientsRepository).FullName, section.OpenIdConnectClientsRepository },
                { typeof(IStoredGrantRepository).FullName, section.StoredGrantRepository }
            };
        }

        protected override IEnumerable<Export> GetExportsCore(ImportDefinition definition, AtomicComposition atomicComposition)
        {
            var exports = new List<Export>();

            string implementingType;
            if (_mappings.TryGetValue(definition.ContractName, out implementingType))
            {
                var t = Type.GetType(implementingType);
                if (t == null)
                {
                    throw new InvalidOperationException("Type not found for interface: " + definition.ContractName);
                }

                var instance = t.GetConstructor(Type.EmptyTypes).Invoke(null);
                var exportDefintion = new ExportDefinition(definition.ContractName, new Dictionary<string, object>());
                var toAdd = new Export(exportDefintion, () => instance);

                exports.Add(toAdd);
            }

            return exports;
        }
    }
}