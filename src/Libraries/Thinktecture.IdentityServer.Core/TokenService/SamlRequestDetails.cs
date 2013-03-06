using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Thinktecture.IdentityServer.Models;

namespace Thinktecture.IdentityServer.TokenService
{
    public class SamlRequestDetails
    {
        public ClaimsIdentity ClientIdentity { get; set; }
        public string TokenType { get; set; }
        public bool IsActive { get; set; }
        public bool IsKnownRealm { get; set; }
        public EndpointAddress Realm { get; set; }
        public bool UsesSsl { get; set; }
        public bool UsesEncryption { get; set; }
        public X509Certificate2 EncryptingCertificate { get; set; }
        public Uri ReplyToAddress { get; set; }
        public bool IsReplyToFromConfiguration { get; set; }
        public bool ReplyToAddressIsWithinRealm { get; set; }
        public RequestSecurityToken Request { get; set; }
        public bool ClaimsRequested { get; set; }
        public RequestClaimCollection RequestClaims { get; set; }
        public bool IsActAsRequest { get; set; }
        public RelyingParty RelyingPartyRegistration { get; set; }
    }
}
