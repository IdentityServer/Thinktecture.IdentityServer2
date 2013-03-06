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
                           where i.IssuerThumbprint.Equals(x509token.Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)
                                 && i.Enabled
                           select i).FirstOrDefault();

                if (idp != null)
                {
                    return idp.Name;
                }
            }

            return null;
        }

      
    }
}
