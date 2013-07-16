using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Thinktecture.IdentityModel.Oidc
{
    public class OidcAuthorizeResponse
    {
        public bool IsError { get; set; }

        public string Error { get; set; }
        public string Code { get; set; }
        public string State { get; set; }
    }
}
