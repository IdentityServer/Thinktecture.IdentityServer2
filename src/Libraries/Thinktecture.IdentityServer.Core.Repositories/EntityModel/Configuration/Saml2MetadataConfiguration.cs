using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Repositories.Sql.Configuration
{
    public class Saml2MetadataConfiguration
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public bool Enabled { get; set; }
    }
}
