using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Claims;
using System.ServiceModel;

namespace Web.Wcf
{
    [ServiceContract(Name = "ClaimsServiceContract", Namespace = "urn:tt")]
    public interface IClaimsService
    {
        [OperationContract(Name = "GetClaims", Action = "GetClaims", ReplyAction = "GetClaimsReply")]
        List<ClaimDto> GetClaims();

        [OperationContract(Name = "GetClaimsWithDelegation", Action = "GetClaimsWithDelegation", ReplyAction = "GetClaimsWithDelegationReply")]
        Tuple<List<ClaimDto>, List<ClaimDto>> GetClaimsWithDelegation();
    }

    [DataContract(Name = "ClaimDto", Namespace = "urn:tt")]
    public class ClaimDto
    {
        [DataMember]
        public string Type { get; set; }

        [DataMember]
        public string Value { get; set; }

        [DataMember]
        public string Issuer { get; set; }

        [DataMember]
        public string OriginalIssuer { get; set; }
    }

    [ServiceBehavior(Name = "ClaimsService", Namespace = "urn:tt")]
    public class ClaimsService : IClaimsService
    {
        public List<ClaimDto> GetClaims()
        {
            var principal = ClaimsPrincipal.Current;
            if (principal == null)
            {
                throw new SecurityException();
            }

            return new List<ClaimDto>(
                from claim in principal.Claims
                select new ClaimDto
                {
                    Type = claim.Type,
                    Value = claim.Value,
                    Issuer = claim.Issuer,
                    OriginalIssuer = claim.OriginalIssuer,
                });
        }

        public Tuple<List<ClaimDto>, List<ClaimDto>> GetClaimsWithDelegation()
        {
            var originalCallerClaims = GetClaims();
            var directCallerClaims = new List<ClaimDto>();

            var id = ClaimsPrincipal.Current.Identities.First();
            if (id.Actor != null)
            {
                directCallerClaims = new List<ClaimDto>(
                    from claim in id.Actor.Claims
                    select new ClaimDto
                    {
                        Type = claim.Type,
                        Value = claim.Value,
                        Issuer = claim.Issuer,
                        OriginalIssuer = claim.OriginalIssuer,
                    });
            }

            return new Tuple<List<ClaimDto>, List<ClaimDto>>(originalCallerClaims, directCallerClaims);
        }
    }
}