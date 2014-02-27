using System.Configuration;
using System.Web.Profile;
using BrockAllen.MembershipReboot;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace MembershipRebootUserRepository
{
    public class IdentityRepository : 
        IUserRepository,
        IUserManagementRepository,
        IClientCertificatesRepository,
        IClaimsRepository
    {
        private const string ProfileClaimPrefix = "http://identityserver.thinktecture.com/claims/profileclaims/";

        UserAccountService userSvc;
        GroupService groupSvc;
        IUserAccountQuery userQuery;
        IGroupQuery groupQuery;
        
        public IdentityRepository()
        {
            var settings = SecuritySettings.FromConfiguration();
            settings.RequireAccountVerification = false;
            var config = new MembershipRebootConfiguration(settings);
            var uarepo = new BrockAllen.MembershipReboot.Ef.DefaultUserAccountRepository();
            this.userSvc = new UserAccountService(config, uarepo);
            this.userQuery = uarepo;

            var grpRepo = new BrockAllen.MembershipReboot.Ef.DefaultGroupRepository();
            this.groupSvc = new GroupService(config.DefaultTenant, grpRepo);
            this.groupQuery = grpRepo;
        }

        public IdentityRepository(UserAccountService userSvc, GroupService groupSvc)
        {
            this.userSvc = userSvc;
            this.groupSvc = groupSvc;
        }

        #region IUserRepository
        public IEnumerable<string> GetRoles(string userName)
        {
            var user = userSvc.GetByUsername(userName);
            if (user != null)
            {
                return user.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x=>x.Value);
            }
            return Enumerable.Empty<string>();
        }

        public bool ValidateUser(System.Security.Cryptography.X509Certificates.X509Certificate2 clientCertificate, out string userName)
        {
            UserAccount user;
            if (userSvc.AuthenticateWithCertificate(clientCertificate, out user))
            {
                userName = user.Username;
                return true;
            }

            userName = null;
            return false;
        }

        public bool ValidateUser(string userName, string password)
        {
            return userSvc.Authenticate(userName, password);
        }
        #endregion

        #region IUserManagementRepository

        public void CreateRole(string roleName)
        {
            groupSvc.Create(roleName);
        }

        public void CreateUser(string userName, string password, string email = null)
        {
            userSvc.CreateAccount(userName, password, email);
        }

        public void DeleteRole(string roleName)
        {
            var grp = groupSvc.Get(roleName);
            if (grp != null)
            {
                groupSvc.Delete(grp.ID);
            }
        }

        public void DeleteUser(string userName)
        {
            var user = userSvc.GetByUsername(userName);
            if (user != null)
            {
                userSvc.DeleteAccount(user.ID);
            }
        }

        public IEnumerable<string> GetRoles()
        {
            return groupQuery.GetRoleNames(userSvc.Configuration.DefaultTenant);
        }

        public IEnumerable<string> GetRolesForUser(string userName)
        {
            var user = userSvc.GetByUsername(userName);
            if (user != null)
            {
                return user.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value);
            }
            return Enumerable.Empty<string>();
        }

        public IEnumerable<string> GetUsers(int start, int count, out int totalCount)
        {
            if (start < 1) start = 0;
            if (count < 0) count = 10;
            start = (start - 1) * count;
            return userQuery.Query(userSvc.Configuration.DefaultTenant, null, start, count, out totalCount).Select(x => x.Username);
        }

        public IEnumerable<string> GetUsers(string filter, int start, int count, out int totalCount)
        {
            if (start < 1) start = 1;
            if (count < 0) count = 10;
            start = (start - 1) * count;
            return userQuery.Query(userSvc.Configuration.DefaultTenant, filter, start, count, out totalCount).Select(x => x.Username);
        }

        public void SetPassword(string userName, string password)
        {
            var user = userSvc.GetByUsername(userName);
            if (user != null)
            {
                userSvc.SetPassword(user.ID, password);
            }
        }

        public void SetRolesForUser(string userName, IEnumerable<string> roles)
        {
            var user = userSvc.GetByUsername(userName);
            if (user != null)
            {
                userSvc.RemoveClaim(user.ID, ClaimTypes.Role);
                if (roles != null)
                {
                    foreach (var role in roles)
                    {
                        userSvc.AddClaim(user.ID, ClaimTypes.Role, role);
                    }
                }
            }
        }
        #endregion

        #region IClientCertificatesRepository
        public void Add(Thinktecture.IdentityServer.Models.ClientCertificate certificate)
        {
            var user = userSvc.GetByUsername(certificate.UserName);
            if (user != null)
            {
                userSvc.AddCertificate(user.ID, certificate.Thumbprint, certificate.Description);
            }
        }

        public void Delete(Thinktecture.IdentityServer.Models.ClientCertificate certificate)
        {
            var user = userSvc.GetByUsername(certificate.UserName);
            if (user != null)
            {
                userSvc.RemoveCertificate(user.ID, certificate.Thumbprint);
            }
        }

        public IEnumerable<Thinktecture.IdentityServer.Models.ClientCertificate> GetClientCertificatesForUser(string userName)
        {
            var user = userSvc.GetByUsername(userName);
            if (user != null)
            {
                return user.Certificates.Select(x => new Thinktecture.IdentityServer.Models.ClientCertificate() { UserName = user.Username, Thumbprint = x.Thumbprint, Description = x.Subject });
            }
            return Enumerable.Empty<Thinktecture.IdentityServer.Models.ClientCertificate>();
        }

        public IEnumerable<string> List(int pageIndex, int pageSize)
        {
            if (pageIndex < 1) pageIndex = 1;
            if (pageSize < 0) pageSize = 10;
            int skip = pageSize * (pageIndex-1);
            int totalCount;
            return userQuery.Query(userSvc.Configuration.DefaultTenant, null, skip, pageSize, out totalCount).Select(x => x.Username);
        }

        public bool SupportsWriteAccess
        {
            get { return true; }
        }

        public bool TryGetUserNameFromThumbprint(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate, out string userName)
        {
            UserAccount user;
            if (userSvc.AuthenticateWithCertificate(certificate, out user))
            {
                userName = user.Username;
                return true;
            }
            userName = null;
            return false;
        }
        #endregion

        #region IClaimsRepository
        public IEnumerable<Claim> GetClaims(
            ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            var user = userSvc.GetByUsername(principal.Identity.Name);
            if (user == null) throw new ArgumentException("Invalid Username");

            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, user.Username));
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.ID.ToString("D")));
            if (!String.IsNullOrWhiteSpace(user.Email))
            {
                claims.Add(new Claim(ClaimTypes.Email, user.Email));
            }
            if (!String.IsNullOrWhiteSpace(user.MobilePhoneNumber))
            {
                claims.Add(new Claim(ClaimTypes.MobilePhone, user.MobilePhoneNumber));
            }
            //var x509 = from c in user.Certificates
            //           select new Claim(ClaimTypes.X500DistinguishedName, c.Subject);
            //claims.AddRange(x509);
            var otherClaims =
                (from uc in user.Claims
                 select new Claim(uc.Type, uc.Value)).ToList();
            claims.AddRange(otherClaims);

            return claims;
        }

        public IEnumerable<string> GetSupportedClaimTypes()
        {
            //var query =
            //    from u in userSvc.GetAll()
            //    from c in u.Claims
            //    select c.Type;

            return
                new string[] { ClaimTypes.Name, ClaimTypes.Email, ClaimTypes.MobilePhone, ClaimTypes.Role };
                //.Union(query.Distinct()).Distinct();
        }

        public IEnumerable<ProfileProperty> GetProfileProperties()
        {
            var properties = new List<ProfileProperty>();

            if (ProfileManager.Enabled)
            {
                foreach (SettingsProperty prop in ProfileBase.Properties)
                {
                    properties.Add(new ProfileProperty() { Name = prop.Name, PropertyType = prop.PropertyType });
                }
            }
            else
            {
                throw new NotImplementedException();
            }

            return properties;
        }

        public virtual IEnumerable<ProfileProperty> GetProfileProperties(string userName)
        {
            
            var user = userSvc.GetByUsername(userName);
            if (user == null) throw new ArgumentException("Invalid Username");

            var profileClaims =
                (from uc in user.Claims
                 select new ProfileProperty() { Name = GetProfileClaimName(uc.Type), PropertyType = typeof(String), Value = uc.Value }).ToList();

            var properties = new List<ProfileProperty>();

            if (ProfileManager.Enabled)
            {
                foreach (SettingsProperty prop in ProfileBase.Properties)
                {
                    if (profileClaims.Exists(claim => claim.Name.Equals(prop.Name, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        var profileClaim = profileClaims.Single(claim => claim.Name.Equals(prop.Name, StringComparison.InvariantCultureIgnoreCase));
                        profileClaim.Name = prop.Name;
                        properties.Add(profileClaim);
                    }
                    else
                    {
                        properties.Add(new ProfileProperty() { Name = prop.Name, PropertyType = prop.PropertyType});
                    }
                }
            }
            else
            {
                throw new NotImplementedException();
            }
            
            return properties;
        }

        public void UpdateProfileProperties(string userName, ProfileProperty[] profileProperties)
        {
            var user = userSvc.GetByUsername(userName);
            if (user == null) throw new ArgumentException("Invalid Username");

            for (int i = 0; i < profileProperties.Length; i++)
            {
                if (String.IsNullOrWhiteSpace(Convert.ToString(profileProperties[i].Value)))
                {
                    userSvc.RemoveClaim(user.ID, GetProfileClaimType(profileProperties[i].Name));
                }
                else
                {
                    userSvc.RemoveClaim(user.ID, GetProfileClaimType(profileProperties[i].Name));
                    userSvc.AddClaim(user.ID, GetProfileClaimType(profileProperties[i].Name), Convert.ToString(profileProperties[i].Value));
                }
            }
        }

        #endregion

        protected string GetProfileClaimName(string propertyType)
        {
            return propertyType.Split('/').Last();
        }

        protected string GetProfileClaimType(string propertyName)
        {
            return string.Format("{0}{1}", ProfileClaimPrefix, propertyName.ToLower());
        }
    }
}
