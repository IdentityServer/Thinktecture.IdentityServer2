using System;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Description;
using Thinktecture.IdentityModel.WSTrust;
using Web.Wcf;

namespace Client
{
    class Program
    {
        static string _idsrvEndpoint = "https://identity.thinktecture.com/idsrvsample/issue/wstrust/mixed/username";
        static string _realm = "https://samples.thinktecture.com/mvc/";

        static void Main(string[] args)
        {
            var token = RequestToken();
            CallService(token);
        }

        private static void CallService(SecurityToken token)
        {
            var serviceEndpoint = "https://" + "adfs.leastprivilege.vm" + "/rp/service.svc";
            
            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;

            var factory = new ChannelFactory<IClaimsService>(
                binding,
                new EndpointAddress(serviceEndpoint));
            factory.Credentials.SupportInteractive = false;

            var channel = factory.CreateChannelWithIssuedToken(token);
            var claims = channel.GetClaims();

            claims.ForEach(c => Console.WriteLine("{0}\n {1}\n\n", c.Type, c.Value));
        }

        private static SecurityToken RequestToken()
        {
            var binding = new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential);
            
            var credentials = new ClientCredentials();
            credentials.UserName.UserName = "bob";
            credentials.UserName.Password = "abc!123";

            return WSTrustClient.Issue(
                new EndpointAddress(_idsrvEndpoint),
                new EndpointAddress(_realm),
                binding,
                credentials);
        }
    }
}
