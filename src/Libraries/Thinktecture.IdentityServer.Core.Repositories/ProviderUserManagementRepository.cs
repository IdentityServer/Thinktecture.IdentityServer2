using System;
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

            if (roles.Any())
            {
                Roles.AddUserToRoles(userName, roles.ToArray());
            }
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

        public IEnumerable<string> GetUsers(int start, int count, out int totalCount)
        {
            var items = Membership.GetAllUsers(start, count, out totalCount).OfType<MembershipUser>();
            return items.Select(x => x.UserName);
        }

        public IEnumerable<string> GetUsers(string filter, int start, int count, out int totalCount)
        {
            var items = Membership.GetAllUsers().OfType<MembershipUser>();
            var query =
                from user in items
                where user.UserName.Contains(filter) ||
                      (user.Email != null && user.Email.Contains(filter))
                select user.UserName;
            totalCount = query.Count();
            return query.Skip(start).Take(count);
        }

        public void SetPassword(string userName, string password)
        {
            if (String.IsNullOrEmpty(userName))
            {
                throw new ValidationException("Username is required");
            }
            if (String.IsNullOrEmpty(password))
            {
                throw new ValidationException("Password is required");
            }
            
            ValidatePasswordStrength(password);

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

        private static void ValidatePasswordStrength(string password)
        {
            var provider = Membership.Provider;
            if (password.Length < provider.MinRequiredPasswordLength)
            {
                throw new ValidationException(String.Format("{0} is the minimum password length", provider.MinRequiredPasswordLength));
            }
            if (provider.MinRequiredNonAlphanumericCharacters > 0)
            {
                int num2 = 0;
                for (int i = 0; i < password.Length; i++)
                {
                    if (!char.IsLetterOrDigit(password[i]))
                    {
                        num2++;
                    }
                }
                if (num2 < provider.MinRequiredNonAlphanumericCharacters)
                {
                    throw new ValidationException(String.Format("{0} is the minimum number of non-alphanumeric characters", provider.MinRequiredNonAlphanumericCharacters));
                }
            }
            if (!String.IsNullOrWhiteSpace(provider.PasswordStrengthRegularExpression) &&
                !System.Text.RegularExpressions.Regex.IsMatch(password, provider.PasswordStrengthRegularExpression))
            {
                throw new ValidationException(String.Format("Password does not match the regular expression {0}", provider.PasswordStrengthRegularExpression));
            }
        }
    }
}
