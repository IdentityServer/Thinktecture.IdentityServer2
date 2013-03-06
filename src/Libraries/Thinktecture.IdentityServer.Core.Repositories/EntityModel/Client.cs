using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    public class Client
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Name { get; set; }
        
        [Required]
        public string Description { get; set; }

        [Required]
        public string ClientId { get; set; }

        [Required]
        public string ClientSecret { get; set; }

        public string RedirectUri { get; set; }

        [Required]
        public bool NativeClient { get; set; }

        [Required]
        public bool AllowImplicitFlow { get; set; }

        [Required]
        public bool AllowResourceOwnerFlow { get; set; }

        [Required]
        public bool AllowCodeFlow { get; set; }
    }
}