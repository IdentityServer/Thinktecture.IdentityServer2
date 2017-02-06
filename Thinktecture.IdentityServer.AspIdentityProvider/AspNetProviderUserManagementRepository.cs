using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Configuration.Provider;
using System.Linq;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.AspIdentityProvider
{
    public class AspNetProviderUserManagementRepository : IUserManagementRepository
    {
        private readonly RoleManager<IdentityRole> _roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(ApplicationDbContext.Create()));
        private readonly UserManager<IdentityUser> _userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(ApplicationDbContext.Create()));


        public AspNetProviderUserManagementRepository()
        {
            _userManager.UserTokenProvider = new TotpSecurityStampBasedTokenProvider<IdentityUser, string>();
            _userManager.PasswordValidator = new CustomPasswordValidator(8);
        }
        public void CreateRole(string roleName)
        {
            try
            {
                _roleManager.Create(new IdentityRole(roleName));
            }
            catch (ProviderException)
            {
            }
        }

        public void CreateUser(string userName, string password, string email = null)
        {
            try
            {
                IdentityUser user = new IdentityUser { UserName = userName, Email = email };
                var result = _userManager.Create(user, password);
                if (!result.Succeeded)
                {
                    throw new ValidationException("Unable to create user");
                }
            }
            catch (Exception ex)
            {
                throw new ValidationException(ex.Message);
            }
        }

        public void DeleteRole(string roleName)
        {
            try
            {
                IdentityRole role = _roleManager.FindByName(roleName);
                if (role != null)
                    _roleManager.Delete(role);
            }
            catch (ProviderException)
            {
            }
        }

        public void DeleteUser(string userName)
        {
            IdentityUser user = _userManager.FindByName(userName);
            if (user != null)
                _userManager.Delete(user);
        }

        public IEnumerable<string> GetRoles()
        {
            List<string> roles = new List<string>();
            foreach (var identityRole in _roleManager.Roles)
            {
                roles.Add(identityRole.Name);
            }
            return roles;
        }

        public IEnumerable<string> GetRolesForUser(string userName)
        {
            var user = _userManager.FindByName(userName);
            return _userManager.GetRoles(user.Id);
        }

        public IEnumerable<string> GetUsers(int pageIndex, int count, out int totalCount)
        {
            var users = _userManager.Users.OrderBy(t => t.Id).Skip(pageIndex).Take(count).ToList();
            totalCount = _userManager.Users.Count();

            return users.Select(x => x.UserName);
        }

        public IEnumerable<string> GetUsers(string filter, int pageIndex, int count, out int totalCount)
        {
            var items = _userManager.Users;
            filter = filter.ToLower();
            IEnumerable<string> query =
                from user in items
                where user.UserName.ToLower().Contains(filter) ||
                      (user.Email != null && user.Email.ToLower().Contains(filter))
                select user.UserName;
            totalCount = query.Count();
            return query.Skip(pageIndex * count).Take(count);
        }

        public void SetPassword(string userName, string password)
        {
            if (String.IsNullOrEmpty(userName))
                throw new ValidationException("Username is required");
            if (String.IsNullOrEmpty(password))
                throw new ValidationException("Password is required");

            var validationResult = _userManager.PasswordValidator.ValidateAsync(password).Result;
            if (!validationResult.Succeeded)
            {
                throw new ValidationException(String.Join(", ", validationResult.Errors));
            }

            try
            {
                var user = _userManager.FindByName(userName);
                if (user != null)
                {
                    var code = _userManager.GeneratePasswordResetToken(user.Id);
                    var result = _userManager.ResetPassword(user.Id, code, password);
                    if (!result.Succeeded)
                    {
                        throw new ValidationException(String.Join(", ", result.Errors));
                    }
                }
            }
            catch (Exception mex)
            {
                throw new ValidationException(mex.Message, mex);
            }
        }

        public void SetRolesForUser(string userName, IEnumerable<string> roles)
        {
            var user = _userManager.FindByName(userName);
            if (user != null)
            {
                string[] userRoles = GetRolesForUser(userName).ToArray();

                if (userRoles.Length != 0)
                {
                    foreach (var role in userRoles)
                    {
                        _userManager.RemoveFromRole(user.Id, role);
                    }

                }

                foreach (var role in roles)
                {
                    _userManager.AddToRole(user.Id, role);
                }
            }
        }
    }
}