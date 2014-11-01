using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.AspIdentityProvider
{
    public class AspNetProviderUserRepository : IUserRepository
    {
        public AspNetProviderUserRepository()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        [Import]
        public IClientCertificatesRepository Repository { get; set; }

        private readonly UserManager<IdentityUser> _userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(ApplicationDbContext.Create()));

        public virtual IEnumerable<string> GetRoles(string userName)
        {
            List<string> returnedRoles = new List<string>();

            IdentityUser user = _userManager.FindByName(userName);
            if (user != null)
            {
                IList<string> roles = _userManager.GetRoles(user.Id);
                returnedRoles = roles.Where(role => role.StartsWith(Constants.Roles.InternalRolesPrefix)).ToList();
            }

            return returnedRoles;
        }


        public virtual bool ValidateUser(string userName, string password)
        {
            return _userManager.Find(userName, password) != null;
        }

        public virtual bool ValidateUser(X509Certificate2 clientCertificate, out string userName)
        {
            return Repository.TryGetUserNameFromThumbprint(clientCertificate, out userName);
        }
    }
}