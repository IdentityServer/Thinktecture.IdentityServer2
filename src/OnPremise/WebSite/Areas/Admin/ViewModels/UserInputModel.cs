using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class UserInputModel
    {

        [Display(ResourceType = typeof(Resources.UserInputModel), Name = "Username")]
        [Required]
        public string Username { get; set; }

        [Display(ResourceType = typeof(Resources.UserInputModel), Name = "Password")]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(ResourceType = typeof(Resources.UserInputModel), Name = "Email")]
        public string Email { get; set; }

        [ScaffoldColumn(false)]
        public UserRoleAssignment[] Roles { get; set; }
    }
}