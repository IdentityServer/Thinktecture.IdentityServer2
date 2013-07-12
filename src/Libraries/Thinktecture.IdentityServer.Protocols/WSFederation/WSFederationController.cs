/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.Composition;
using System.IdentityModel.Services;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Protocols.WSFederation
{
    [ClaimsAuthorize(Constants.Actions.Issue, Constants.Resources.WSFederation)]
    public class WSFederationController : Controller
    {


        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public WSFederationController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public WSFederationController(IConfigurationRepository configurationRepository)
        {
            ConfigurationRepository = configurationRepository;
        }

        public ActionResult Issue()
        {
            Tracing.Verbose("WS-Federation endpoint called.");

            if (!ConfigurationRepository.WSFederation.Enabled && ConfigurationRepository.WSFederation.EnableAuthentication)
            {
                return new HttpNotFoundResult();
            }

            var message = WSFederationMessage.CreateFromUri(HttpContext.Request.Url);

            // sign in 
            var signinMessage = message as SignInRequestMessage;
            if (signinMessage != null)
            {
                return ProcessWSFederationSignIn(signinMessage, ClaimsPrincipal.Current);
            }

            // sign out
            var signoutMessage = message as SignOutRequestMessage;
            if (signoutMessage != null)
            {
                return ProcessWSFederationSignOut(signoutMessage);
            }

            return View("Error");
        }

        protected virtual string _cookieName 
        {
            get { return @"wsfedsignout"; }
        }

        #region Helper
        private ActionResult ProcessWSFederationSignIn(SignInRequestMessage message, ClaimsPrincipal principal)
        {
            // issue token and create ws-fed response
            var response = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                message,
                principal as ClaimsPrincipal,
                TokenServiceConfiguration.Current.CreateSecurityTokenService());

            // set cookie for single-sign-out
            new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime)
                .AddEndpoint(response.BaseUri.AbsoluteUri);

            return new WSFederationResult(response, requireSsl: ConfigurationRepository.WSFederation.RequireSslForReplyTo);
        }

        private ActionResult ProcessWSFederationSignOut(SignOutRequestMessage message)
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();

            // check for return url
            if (!string.IsNullOrWhiteSpace(message.Reply))
            {
                ViewBag.ReturnUrl = message.Reply;
            }

            // check for existing sign in sessions
            var mgr = new SignInSessionsManager(HttpContext, _cookieName);
            var realms = mgr.GetEndpoints();
            mgr.ClearEndpoints();
            
            return View("Signout", realms);
        }
        #endregion
    }
}
