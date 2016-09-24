using System.Linq;
using System.Security.Claims;

namespace Thinktecture.IdentityServer.Protocols.WSTrust
{
    /// <summary>
    /// Provides claims management for the federation provider token service.
    /// </summary>
    internal sealed class FederatedClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            string issuerName = incomingPrincipal.Claims.First().Issuer;

            var identity = incomingPrincipal.Identities.First();

            identity.AddClaim(new Claim(Constants.Claims.IdentityProvider, issuerName, ClaimValueTypes.String, Constants.InternalIssuer));

            return base.Authenticate(resourceName, incomingPrincipal);
        }
    }
}
