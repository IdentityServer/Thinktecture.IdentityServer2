using Microsoft.ServiceBus.Messaging;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using Thinktecture.IdentityModel.Extensions;
using Thinktecture.IdentityModel.Tokens;

namespace SimpleHttpClient
{
    class Program
    {
        static string signingKey = "B53SdrIWPPByja1vEkthfaGklA9VSugBey9otvzSAaY=";
        static string realm = "http://sbserver/swttest/";
        static string issuerUri = "http://identityserver.v2.thinktecture.com/samples";
        static string simpleHttpEndpoint = "https://idsrv.local/issue/simple";


        static void Main(string[] args)
        {
            var token = GetToken();
            
            // swt parsing and validationn
            ValidateSwtToken(token);
            //UseServiceBus(token)

            Console.ReadLine();
        }

        private static string GetToken()
        {
            "Requesting token".ConsoleYellow();

            var client = new HttpClient
            {
                BaseAddress = new Uri(simpleHttpEndpoint)
            };

            client.SetBasicAuthentication("bob", "abc!123");

            var response = client.GetAsync("?realm=http://sbserver/swttest/&tokentype=swt").Result;
            response.EnsureSuccessStatusCode();

            var tokenResponse = response.Content.ReadAsStringAsync().Result;
            var token = JObject.Parse(tokenResponse)["access_token"].ToString();

            Console.WriteLine(token);

            return token;
        }

        private static void UseServiceBus(string token)
        {
            StaticSimpleWebTokenProvider tp = new StaticSimpleWebTokenProvider(token);
            
            MessagingFactory factory =
                MessagingFactory.Create("sb://sbserver/swttest/", tp);
            
            var qc = factory.CreateQueueClient("swttest");
            qc.Send(new BrokeredMessage());
        }

        private static void ValidateSwtToken(string tokenString)
        {
            var configuration = new SecurityTokenHandlerConfiguration();
            var validationKey = new InMemorySymmetricSecurityKey(Convert.FromBase64String(signingKey));

            // audience validation
            configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(realm));

            // signature & issuer validation
            var resolverTable = new Dictionary<string, IList<SecurityKey>>
            {
                { issuerUri, new SecurityKey[] { validationKey } }
            };

            configuration.IssuerTokenResolver = new NamedKeyIssuerTokenResolver(resolverTable);

            var handler = new SimpleWebTokenHandler();
            handler.Configuration = configuration;

            var token = handler.ReadToken(tokenString);
            var ids = handler.ValidateToken(token);

            "\n\nValidated Claims:".ConsoleYellow();
            foreach (var claim in ids.First().Claims)
            {
                Console.WriteLine("{0}\n {1}\n", claim.Type, claim.Value);
            }
        }
    }
}
