using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

//Code taken from
//http://blogs.msdn.com/b/webdev/archive/2014/01/06/implementing-custom-password-policy-using-asp-net-identity.aspx

namespace Thinktecture.IdentityServer.AspIdentityProvider
{
    public class CustomPasswordValidator : IIdentityValidator<string>
    {
        public CustomPasswordValidator(int length)
        {
            RequiredLength = length;
        }

        public int RequiredLength { get; set; }

        public Task<IdentityResult> ValidateAsync(string item)
        {
            if (String.IsNullOrEmpty(item) || item.Length < RequiredLength)

                return Task.FromResult(IdentityResult.Failed(String.Format("Password should be of length {0}", RequiredLength)));

            /*
                Passwords will contain at least (1) upper case letter 
                Passwords will contain at least (1) lower case letter 
                Passwords will contain at least (1) number or special character 
                Passwords will contain at least (8) characters in length 
             */
            const string pattern = @"(?=^.{8,}$)((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$";

            if (!Regex.IsMatch(item, pattern))

                return Task.FromResult(IdentityResult.Failed("Password provided is not an strong password"));

            return Task.FromResult(IdentityResult.Success);
        }
    }
}