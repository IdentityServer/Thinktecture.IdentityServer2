using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Security;

namespace Thinktecture.IdentityServer.Repositories
{
    public class ProviderUserManagementRepository : IUserManagementRepository
    {
        public void CreateUser(string userName, string password, string email = null)
        {
            try
            {
                Membership.CreateUser(userName, password, email);
            }
            catch (MembershipCreateUserException ex)
            {
                throw new ValidationException(ex.Message);
            }
        }

        public void DeleteUser(string userName)
        {
            Membership.DeleteUser(userName);
        }

        public void SetRolesForUser(string userName, IEnumerable<string> roles)
        {
            var userRoles = Roles.GetRolesForUser(userName);

            if (userRoles.Length != 0)
            {
                Roles.RemoveUserFromRoles(userName, userRoles);
            }

            Roles.AddUserToRoles(userName, roles.ToArray());
        }

        public IEnumerable<string> GetRolesForUser(string userName)
        {
            return Roles.GetRolesForUser(userName);
        }

        public IEnumerable<string> GetRoles()
        {
            return Roles.GetAllRoles();
        }

        public void CreateRole(string roleName)
        {
            try
            {
                Roles.CreateRole(roleName);
            }
            catch (ProviderException)
            { }
        }

        public void DeleteRole(string roleName)
        {
            try
            {
                Roles.DeleteRole(roleName);
            }
            catch (ProviderException)
            { }
        }

        public IEnumerable<string> GetUsers()
        {
            var items = Membership.GetAllUsers().OfType<MembershipUser>();
            return items.Select(x => x.UserName);
        }

        public IEnumerable<string> GetUsers(string filter)
        {
            var items = Membership.GetAllUsers().OfType<MembershipUser>();
            var query =
                from user in items
                where user.UserName.Contains(filter) ||
                      (user.Email != null && user.Email.Contains(filter))
                select user.UserName;
            return query;
        }


        public void SetPassword(string userName, string password)
        {
            try
            {
                var user = Membership.GetUser(userName);
                user.ChangePassword(user.ResetPassword(), password);
            }
            catch (MembershipPasswordException mex)
            {
                throw new ValidationException(mex.Message, mex);
            }
        }
    }
}
