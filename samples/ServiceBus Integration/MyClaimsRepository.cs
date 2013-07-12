using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Repositories
{
    public class MyClaimsRepository : ProviderClaimsRepository
    {
        string sbClaimType = "net.windows.servicebus.action";

        public override IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            if (requestDetails.Realm.Uri.AbsoluteUri == "http://sbserver/swttest/")
            {
                if (principal.Identity.Name == "bob")
                {
                    return new List<Claim>
                    {
                        new Claim(sbClaimType, "Listen"),
                        new Claim(sbClaimType, "Manage"),
                    };
                }
                else
                {
                    return new List<Claim>
                    {
                        new Claim(sbClaimType, "Send"),
                    };
                }
            }

            return base.GetClaims(principal, requestDetails);
        }
    }
}
