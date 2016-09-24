using System;
using System.ComponentModel.Composition;
using System.IdentityModel.Configuration;
using System.Reflection;
using System.ServiceModel.Activation;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.WSTrust
{
    /// <summary>
    /// Provides common functionality for the identity provider and federation provider factories.
    /// </summary>
    public abstract class TokenServiceHostFactoryBase : ServiceHostFactory
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public TokenServiceHostFactoryBase()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        protected virtual SecurityTokenServiceConfiguration CreateSecurityTokenServiceConfiguration(string constructorString)
        {
            Type type = Type.GetType(constructorString, true);
            if (!type.IsSubclassOf(typeof(SecurityTokenServiceConfiguration)))
            {
                throw new InvalidOperationException("SecurityTokenServiceConfiguration");
            }

            return (Activator.CreateInstance(
                type,
                BindingFlags.CreateInstance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance,
                null,
                null,
                null) as SecurityTokenServiceConfiguration);
        }
    }
}
