using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using Thinktecture.IdentityServer.Models;

namespace Thinktecture.IdentityServer.TokenService
{
    public class IdentityProviderIssuerNameRegistry : IssuerNameRegistry
    {
        IEnumerable<IdentityProvider> _idps;

        public IdentityProviderIssuerNameRegistry(IEnumerable<IdentityProvider> identityProviders)
        {
            _idps = identityProviders;
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            var x509token = securityToken as X509SecurityToken;
            if (x509token != null)
            {
                var idp = (from i in _idps
                           where i.Enabled && 
                                 IsValidThumbprint(i.IssuerThumbprint, x509token.Certificate.Thumbprint)
                           select i).FirstOrDefault();

                if (idp != null)
                {
                    return idp.Name;
                }
            }

            return null;
        }

        private bool IsValidThumbprint(string issuerThumbprints, string x509Thumbprint)
        {
            return issuerThumbprints.Split(new[] {'\r', '\n'}, StringSplitOptions.RemoveEmptyEntries)
                .Any(x => x.Equals(x509Thumbprint, StringComparison.OrdinalIgnoreCase));
        }
    }
}
