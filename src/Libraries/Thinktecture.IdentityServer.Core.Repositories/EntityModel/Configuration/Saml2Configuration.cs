using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Repositories.Sql.Configuration
{
    public class Saml2Configuration
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public bool Enabled { get; set; }

        [Required]
        public bool EnableAuthentication { get; set; }

        [Required]
        public bool EnableFederation { get; set; }

        [Required]
        public bool EnableHrd { get; set; }

        [Required]
        public bool AllowReplyTo { get; set; }

        [Required]
        public Boolean RequireReplyToWithinRealm { get; set; }
        
        [Required]
        public Boolean RequireSslForReplyTo { get; set; }
    }
}
