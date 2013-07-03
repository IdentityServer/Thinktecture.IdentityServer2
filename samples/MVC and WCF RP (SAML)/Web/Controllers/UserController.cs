using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Claims;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using Thinktecture.IdentityModel.WSTrust;
using Web.Wcf;

namespace Web.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        public ActionResult Index()
        {
            return View("Identity", HttpContext.User);
        }

        public ActionResult Token()
        {
            string tokenString;
            
            try
            {
                tokenString = GetBootstrapTokenAsString(User.Identity as ClaimsIdentity);
            }
            catch (Exception ex)
            {
                return new ContentResult
                {
                    Content = ex.Message
                };
            }

            return new ContentResult
            {
                ContentType = "text/xml",
                Content = tokenString
            };
        }

        public ActionResult Delegation()
        {
            var id = HttpContext.User.Identity as ClaimsIdentity;
            if (id.BootstrapContext == null)
            {
                ViewBag.Message = "No bootstrap token";
                return View();
            }

            ViewBag.Message = "Press 'call service' to delegate identity to backend service";
            return View();
        }

        [HttpPost]
        public ActionResult Delegation(FormCollection form)
        {
            var id = HttpContext.User.Identity as ClaimsIdentity;
            if (id.BootstrapContext == null)
            {
                ViewBag.Message = "No bootstrap token";
                return View();
            }

            var token = GetActAsToken(id.BootstrapContext as BootstrapContext);

            var proxy = GetServiceProxy(token);
            var result = proxy.GetClaimsWithDelegation();

            ViewBag.Claims = result;
            ViewBag.Message = "Success!";

            return View();
        }

        public ActionResult Signout()
        {
            var fam = FederatedAuthentication.WSFederationAuthenticationModule;

            // clear local cookie
            fam.SignOut(false);

            // initiate a federated sign out request to the sts.
            var signOutRequest = new SignOutRequestMessage(new Uri(fam.Issuer), fam.Realm);
            signOutRequest.Reply = fam.Reply;

            return new RedirectResult(signOutRequest.WriteQueryString());
        }

        #region Helper
        private SecurityToken GetActAsToken(BootstrapContext context)
        {
            string stsAddress = "https://identity.thinktecture.com/idsrvsample/issue/wstrust/mixed/username";
            string realm = FederatedAuthentication.FederationConfiguration.WsFederationConfiguration.Realm;
            
            var factory = new WSTrustChannelFactory(
                new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential),
                new EndpointAddress(stsAddress));
            factory.TrustVersion = TrustVersion.WSTrust13;

            factory.Credentials.UserName.UserName = "middletier";
            factory.Credentials.UserName.Password = "abc!123";

            var rst = new RequestSecurityToken
            {
                AppliesTo = new EndpointReference(realm),

                RequestType = RequestTypes.Issue,
                KeyType = KeyTypes.Bearer,
                ActAs = new SecurityTokenElement(context.SecurityToken)
            };

            var channel = factory.CreateChannel();
            var delegationToken = channel.Issue(rst);

            return delegationToken;
        }

        private static IClaimsService GetServiceProxy(SecurityToken token)
        {
            var serviceAddress = FederatedAuthentication.FederationConfiguration.WsFederationConfiguration.Reply + "service.svc";
            
            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;

            var factory = new ChannelFactory<IClaimsService>(
                binding,
                new EndpointAddress(serviceAddress));
            factory.Credentials.SupportInteractive = false;

            var channel = factory.CreateChannelWithIssuedToken(token);
            return channel;
        }

        private string GetBootstrapTokenAsString(ClaimsIdentity identity)
        {
            var context = identity.BootstrapContext as BootstrapContext;

            if (context == null)
            {
                throw new InvalidOperationException("Bootstrap context is null");
            }

            if (!string.IsNullOrWhiteSpace(context.Token))
            {
                return context.Token;
            }

            var sb = new StringBuilder(128);
            context.SecurityTokenHandler.WriteToken(
                new XmlTextWriter(new StringWriter(sb)),
                context.SecurityToken);

            return sb.ToString();
        }
        #endregion
    }
}
