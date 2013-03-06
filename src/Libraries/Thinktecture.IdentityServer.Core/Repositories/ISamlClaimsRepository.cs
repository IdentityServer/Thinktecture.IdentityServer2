using System.Collections.Generic;
using Thinktecture.IdentityServer.TokenService;
using Claim = System.Security.Claims.Claim;
using ClaimsPrincipal = System.Security.Claims.ClaimsPrincipal;

namespace Thinktecture.IdentityServer.Repositories
{
    /// <summary>
    /// Repository for emitting claims into an outgoing token and claims metadata
    /// </summary>
    public interface ISamlClaimsRepository
    {
        IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, SamlRequestDetails requestDetails);
        IEnumerable<string> GetSupportedClaimTypes();
        
    }
}
