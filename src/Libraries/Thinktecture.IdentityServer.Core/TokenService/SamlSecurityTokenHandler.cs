using System;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Thinktecture.IdentityServer.TokenService
{
    public class SamlSecurityTokenHandler : Saml2SecurityTokenHandler
    {
        protected override void ValidateConfirmationData(Saml2SubjectConfirmationData confirmationData)
        {
            confirmationData.Recipient = new Uri("http://foo");
           // base.ValidateConfirmationData(confirmationData);
        }
      
    }
}
