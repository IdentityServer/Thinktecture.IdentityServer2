using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace Thinktecture.IdentityServer.AspIdentityProvider
{
    public class ApplicationRoleManager : RoleManager<IdentityRole>
    {
        public ApplicationRoleManager(IRoleStore<IdentityRole, string> store)
            : base(store)
        {
        }

        public static ApplicationRoleManager Create()
        {
            return new ApplicationRoleManager(new RoleStore<IdentityRole>(ApplicationDbContext.Create()));
        }
    }
}
