using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class RoleInputModel
    {
        [Display(ResourceType = typeof(Resources.RoleInputModel), Name = "Name")]
        [Required]
        public string Name { get; set; }
        
        [System.Web.Mvc.HiddenInput(DisplayValue=false)]
        public bool Delete { get; set; }
        [System.Web.Mvc.HiddenInput(DisplayValue = false)]
        public bool CanDelete
        {
            get
            {
                if (Name == null) return false;
                return !Name.StartsWith(Thinktecture.IdentityServer.Constants.Roles.InternalRolesPrefix);
            }
        }
    }
}