using Microsoft.AspNet.Identity.EntityFramework;

namespace Thinktecture.IdentityServer.AspIdentityProvider
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext()
            : base("ProviderDB", throwIfV1Schema: false)
        {
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
    }
}