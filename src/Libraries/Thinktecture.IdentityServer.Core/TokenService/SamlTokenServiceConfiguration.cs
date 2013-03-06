/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.Composition;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.SecurityTokenService;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.TokenService
{
    /// <summary>
    /// Configuration information for the token service
    /// </summary>
    public class SamlTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IIdentityProviderRepository IdentityProviderRepository { get; set; }

        public SamlTokenServiceConfiguration(string issuerName)
        {
            Tracing.Information("Configuring token service");
            Container.Current.SatisfyImportsOnce(this);

            SecurityTokenService = typeof(SamlTokenService);
            DefaultTokenLifetime = TimeSpan.FromHours(ConfigurationRepository.Global.DefaultTokenLifetime);
            MaximumTokenLifetime = TimeSpan.FromDays(ConfigurationRepository.Global.MaximumTokenLifetime);
            DefaultTokenType = ConfigurationRepository.Global.DefaultWSTokenType;

            TokenIssuerName = issuerName;
            SigningCredentials = new X509SigningCredentials(ConfigurationRepository.Keys.SigningCertificate);
        }
        private static SamlTokenServiceConfiguration _current;
        private static string _issuerName;
        public static SamlTokenServiceConfiguration Current
        {
            get { return _current ?? (_current = new SamlTokenServiceConfiguration(_issuerName)); }
        }
    }
}