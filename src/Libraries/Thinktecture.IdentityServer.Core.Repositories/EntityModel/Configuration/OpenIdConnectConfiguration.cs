using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Thinktecture.IdentityServer.Repositories.Sql.Configuration
{
    public class OpenIdConnectConfiguration
    {
        [Key]
        public int Id { get; set; }
        public bool Enabled { get; set; }
    }
}
