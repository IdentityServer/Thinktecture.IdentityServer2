/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using BrockAllen.OAuth2;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.Composition;
using System.IdentityModel.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.UI;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Protocols.WSFederation
{
    public class HrdController : Controller
    {
        const string _cookieName = "hrdsignout";
        const string _cookieNameIdp = "hrdidp";
        const string _cookieNameRememberHrd = "hrdSelection";
        const string _cookieContext = "idsrvcontext";
        const string _cookieOAuthContext = "idsrvoauthcontext";

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IIdentityProviderRepository IdentityProviderRepository { get; set; }


        public HrdController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public HrdController(IConfigurationRepository configurationRepository, IIdentityProviderRepository identityProviderRepository)
        {
            IdentityProviderRepository = identityProviderRepository;
            ConfigurationRepository = configurationRepository;
        }

        #region Protocol Implementation
        [HttpGet]
        [ActionName("Issue")]
        [OutputCache(Location = OutputCacheLocation.None, NoStore = true)]
        public ActionResult ProcessRequest()
        {
            Tracing.Verbose("HRD endpoint called.");

            var message = WSFederationMessage.CreateFromUri(HttpContext.Request.Url);

            // sign in 
            var signinMessage = message as SignInRequestMessage;
            if (signinMessage != null)
            {
                return ProcessSignInRequest(signinMessage);
            }

            // sign out
            var signoutMessage = message as SignOutRequestMessage;
            if (signoutMessage != null)
            {
                return ProcessWSFedSignOutRequest(signoutMessage);
            }

            // sign out cleanup
            var cleanupMessage = message as SignOutCleanupRequestMessage;
            if (cleanupMessage != null)
            {
                return ProcessWSFedSignOutCleanupRequest(cleanupMessage);
            }

            return View("Error");
        }

        [HttpPost]
        [ActionName("Issue")]
        public ActionResult ProcessWSFedResponse()
        {
            var fam = new WSFederationAuthenticationModule();
            fam.FederationConfiguration = new FederationConfiguration();

            if (ConfigurationRepository.Keys.DecryptionCertificate != null)
            {
                var idConfig = new IdentityConfiguration();
                
                idConfig.ServiceTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver(
                     new ReadOnlyCollection<SecurityToken>(new SecurityToken[] { new X509SecurityToken(ConfigurationRepository.Keys.DecryptionCertificate) }), false);
                fam.FederationConfiguration.IdentityConfiguration = idConfig;
            }

            if (fam.CanReadSignInResponse(Request))
            {
                var token = fam.GetSecurityToken(Request);
                return ProcessWSFedSignInResponse(fam.GetSignInResponseMessage(Request), token);
            }

            return View("Error");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("Select")]
        public ActionResult ProcessHRDSelection(string idp, string originalSigninUrl, bool rememberHRDSelection = false)
        {
            Tracing.Verbose("HRD selected: " + idp);

            var uri = new Uri(originalSigninUrl);
            var message = WSFederationMessage.CreateFromUri(uri);
            var signinMessage = message as SignInRequestMessage;

            var ip = GetVisibleIdentityProviders().Where(x => x.Name == idp).FirstOrDefault();
            if (ip == null || signinMessage == null) return View("Error");

            try
            {
                if (rememberHRDSelection)
                {
                    SetRememberHRDCookieValue(idp);
                }

                if (ip.Type == IdentityProviderTypes.WSStar)
                {
                    signinMessage.HomeRealm = ip.Name;
                    return RedirectToWSFedIdentityProvider(ip, signinMessage);
                }

                if (ip.Type == IdentityProviderTypes.OAuth2)
                {
                    return RedirectToOAuth2IdentityProvider(ip, signinMessage);
                }
            }
            catch (Exception ex)
            {
                Tracing.Error(ex.ToString());
            }

            return View("Error");
        }

        [HttpGet]
        [ActionName("OAuthTokenCallback")]
        public async Task<ActionResult> OAuthTokenCallback()
        {
            var ctx = GetOAuthContextCookie();
            var ip = GetEnabledOAuthIdentityProviders().Single(x => x.ID == ctx.IdP);

            var oauth2 = new OAuth2Client(GetProviderTypeFromOAuthProfileTypes(ip.ProviderType.Value), ip.ClientID, ip.ClientSecret);
            var result = await oauth2.ProcessCallbackAsync();
            if (result.Error != null) return View("Error");

            var claims = result.Claims.ToList();
            claims.Add(new Claim(Constants.Claims.IdentityProvider, ip.Name, ClaimValueTypes.String, Constants.InternalIssuer));
            var id = new ClaimsIdentity(claims, "OAuth");
            var cp = new ClaimsPrincipal(id);

            return ProcessOAuthResponse(cp, ctx);
        }

        [HttpGet]
        public ActionResult SignoutRedirect(string rp)
        {
            if (!String.IsNullOrWhiteSpace(rp))
            {
                try
                {
                    var bytes = Convert.FromBase64String(rp);
                    bytes = System.Web.Security.MachineKey.Unprotect(bytes);
                    var url = System.Text.Encoding.UTF8.GetString(bytes);
                    return Redirect(url);
                }
                catch { }
            }
            return ShowSignOutPage(null);
        }
        
        #endregion

        #region Helper
        private ActionResult ProcessSignInRequest(SignInRequestMessage message)
        {
            if (!string.IsNullOrWhiteSpace(message.HomeRealm))
            {
                var idp = GetEnabledIdentityProvider(message.HomeRealm);
                if (idp != null)
                {
                    if (idp.Type == IdentityProviderTypes.WSStar)
                    {
                        return RedirectToWSFedIdentityProvider(message);
                    }
                    else if (idp.Type == IdentityProviderTypes.OAuth2)
                    {
                        return RedirectToOAuth2IdentityProvider(idp, message);
                    }
                }
            }
            else
            {
                var pastHRDSelection = GetRememberHRDCookieValue();
                if (String.IsNullOrWhiteSpace(pastHRDSelection))
                {
                    return ShowHomeRealmSelection(message);
                }
                else
                {
                    return ProcessHomeRealmFromCookieValue(message, pastHRDSelection);
                }
            }

            return View("Error");
        }

        private ActionResult ProcessWSFedSignOutRequest(SignOutRequestMessage message)
        {
            var idp = GetIdpCookie();
            if (string.IsNullOrWhiteSpace(idp))
            {
                return ShowSignOutPage(message.Reply);
            }

            var signOutMessage = new SignOutRequestMessage(new Uri(idp));
            if (!string.IsNullOrWhiteSpace(message.Reply) && IsValidReplyTo(message.Reply))
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(message.Reply);
                bytes = System.Web.Security.MachineKey.Protect(bytes);
                var param = Url.Encode(Convert.ToBase64String(bytes));

                var host = this.ConfigurationRepository.Global.PublicHostName;
                if (String.IsNullOrWhiteSpace(host))
                {
                    host = Request.Headers["host"];
                }

                var builder = new UriBuilder();
                builder.Host = host;
                builder.Scheme = Uri.UriSchemeHttps;
                if (this.ConfigurationRepository.Global.HttpsPort != 443)
                {
                    builder.Port = this.ConfigurationRepository.Global.HttpsPort;
                }
                builder.Path = Request.ApplicationPath;
                if (!builder.Path.EndsWith("/")) builder.Path += "/";
                builder.Path += Thinktecture.IdentityServer.Endpoints.Paths.WSFedHRDSignoutRedirect;
                builder.Query = "rp=" + param;
                signOutMessage.Reply = builder.ToString();
            }

            return Redirect(signOutMessage.WriteQueryString());
        }

        private bool IsValidReplyTo(string url)
        {
            // check to see if the URL is in the RPs we've logged into
            var mgr = new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime);
            return mgr.ContainsUrl(url);
        }

        private ActionResult ProcessWSFedSignOutCleanupRequest(SignOutCleanupRequestMessage message)
        {
            return ShowSignOutPage(message.Reply);
        }

        private ActionResult ShowSignOutPage(string returnUrl)
        {
            var mgr = new SignInSessionsManager(HttpContext, _cookieName);

            // check for return url
            if (!string.IsNullOrWhiteSpace(returnUrl) && mgr.ContainsUrl(returnUrl))
            {
                ViewBag.ReturnUrl = returnUrl;
            }

            // check for existing sign in sessions
            var realms = mgr.GetEndpoints();
            mgr.ClearEndpoints();

            return View("Signout", realms);
        }

        private ActionResult RedirectToWSFedIdentityProvider(SignInRequestMessage request)
        {
            IdentityProvider idp = null;
            if (IdentityProviderRepository.TryGet(request.HomeRealm, out idp) && idp.Enabled)
            {
                return RedirectToWSFedIdentityProvider(idp, request);
            }

            return View("Error");
        }

        private ActionResult RedirectToWSFedIdentityProvider(IdentityProvider identityProvider, SignInRequestMessage request)
        {
            var message = new SignInRequestMessage(new Uri(identityProvider.WSFederationEndpoint), ConfigurationRepository.Global.IssuerUri);
            SetContextCookie(request.Context, request.Reply, request.Realm, identityProvider.WSFederationEndpoint);

            return new RedirectResult(message.WriteQueryString());
        }

        private ActionResult RedirectToOAuth2IdentityProvider(IdentityProvider ip, SignInRequestMessage request)
        {
            var ctx = new OAuth2Context
            {
                Wctx = request.Context,
                Wreply = request.Reply,
                Realm = request.Realm,
                IdP = ip.ID
            };

            SetOAuthContextCookie(ctx);

            var oauth2 = new OAuth2Client(GetProviderTypeFromOAuthProfileTypes(ip.ProviderType.Value), ip.ClientID, ip.ClientSecret);
            switch (ip.ProviderType)
            {
                case OAuth2ProviderTypes.Google:
                    return new OAuth2ActionResult(oauth2, ProviderType.Google, null);
                case OAuth2ProviderTypes.Facebook:
                    return new OAuth2ActionResult(oauth2, ProviderType.Facebook, null);
                case OAuth2ProviderTypes.Live:
                    return new OAuth2ActionResult(oauth2, ProviderType.Live, null);
                case OAuth2ProviderTypes.LinkedIn:
                    return new OAuth2ActionResult(oauth2, ProviderType.LinkedIn, null);
            }

            return View("Error");
        }

        private ActionResult ProcessWSFedSignInResponse(SignInResponseMessage responseMessage, SecurityToken token)
        {
            var principal = ValidateToken(token);
            var issuerName = principal.Claims.First().Issuer;

            principal.Identities.First().AddClaim(
                new Claim(Constants.Claims.IdentityProvider, issuerName, ClaimValueTypes.String, Constants.InternalIssuer));

            var context = GetContextCookie();
            var message = new SignInRequestMessage(new Uri("http://foo"), context.Realm);
            message.Context = context.Wctx;
            message.Reply = context.Wreply;

            // issue token and create ws-fed response
            var wsFedResponse = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                message,
                principal,
                TokenServiceConfiguration.Current.CreateSecurityTokenService());

            // set cookie for single-sign-out
            new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime)
                .AddEndpoint(wsFedResponse.BaseUri.AbsoluteUri);

            // set cookie for idp signout
            SetIdPCookie(context.WsFedEndpoint);

            return new WSFederationResult(wsFedResponse, requireSsl: ConfigurationRepository.WSFederation.RequireSslForReplyTo);
        }

        private ActionResult ProcessOAuthResponse(ClaimsPrincipal principal, Context context)
        {
            var message = new SignInRequestMessage(new Uri("http://foo"), context.Realm);
            message.Context = context.Wctx;
            message.Reply = context.Wreply;

            // issue token and create ws-fed response
            var wsFedResponse = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                message,
                principal,
                TokenServiceConfiguration.Current.CreateSecurityTokenService());

            // set cookie for single-sign-out
            new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime)
                .AddEndpoint(wsFedResponse.BaseUri.AbsoluteUri);

            return new WSFederationResult(wsFedResponse, requireSsl: ConfigurationRepository.WSFederation.RequireSslForReplyTo);
        }

        #region Internal
        ProviderType GetProviderTypeFromOAuthProfileTypes(OAuth2ProviderTypes type)
        {
            switch (type)
            {
                case OAuth2ProviderTypes.Facebook: return ProviderType.Facebook;
                case OAuth2ProviderTypes.Live: return ProviderType.Live;
                case OAuth2ProviderTypes.Google: return ProviderType.Google;
                case OAuth2ProviderTypes.LinkedIn: return ProviderType.LinkedIn;
                default: throw new Exception("Invalid OAuthProfileTypes");
            }
        }

        IdentityProvider GetEnabledIdentityProvider(string homeRealm)
        {
            IdentityProvider idp;
            if (IdentityProviderRepository.TryGet(homeRealm, out idp))
            {
                if (idp.Enabled) return idp;
            }

            return null;
        }

        IEnumerable<IdentityProvider> GetEnabledWSIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.Type == IdentityProviderTypes.WSStar);
        }
        IEnumerable<IdentityProvider> GetEnabledOAuthIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.Type == IdentityProviderTypes.OAuth2);
        }

        IEnumerable<IdentityProvider> GetVisibleIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.ShowInHrdSelection);
        }

        private ClaimsPrincipal ValidateToken(SecurityToken token)
        {
            var config = new SecurityTokenHandlerConfiguration();
            config.AudienceRestriction.AudienceMode = AudienceUriMode.Always;
            config.AudienceRestriction.AllowedAudienceUris.Add(new Uri(ConfigurationRepository.Global.IssuerUri));
            
            var registry = new IdentityProviderIssuerNameRegistry(GetEnabledWSIdentityProviders());
            config.IssuerNameRegistry = registry;
            config.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            config.CertificateValidator = X509CertificateValidator.None;

            var handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection(config);
            var identity = handler.ValidateToken(token).First();

            return new ClaimsPrincipal(identity);
        }

        private ActionResult ShowHomeRealmSelection(SignInRequestMessage message)
        {
            var idps = GetVisibleIdentityProviders();
            if (idps.Count() == 1)
            {
                var ip = idps.First();
                message.HomeRealm = ip.Name;
                Tracing.Verbose("Only one HRD option available: " + message.HomeRealm);
                if (ip.Type == IdentityProviderTypes.WSStar)
                {
                    return RedirectToWSFedIdentityProvider(ip, message);
                }
                else if (ip.Type == IdentityProviderTypes.OAuth2)
                {
                    return RedirectToOAuth2IdentityProvider(ip, message);
                }
                else
                {
                    throw new Exception("Invalid IdentityProviderType");
                }
            }
            else
            {
                Tracing.Verbose("HRD selection screen displayed.");
                var vm = new HrdViewModel(message, idps);
                return View("HRD", vm);
            }
        }
        #endregion
        #endregion

        #region Cookies
        private void SetIdPCookie(string url)
        {
            var cookie = new HttpCookie(_cookieNameIdp, url)
            {
                Secure = true,
                HttpOnly = true,
                Path = HttpRuntime.AppDomainAppVirtualPath
            };

            Response.Cookies.Add(cookie);
        }

        private string GetIdpCookie()
        {
            var cookie = Request.Cookies[_cookieNameIdp];
            if (cookie == null)
            {
                return null;
            }

            var idp = cookie.Value;

            cookie.Value = "";
            cookie.Expires = new DateTime(2000, 1, 1);
            cookie.Path = HttpRuntime.AppDomainAppVirtualPath;
            Response.SetCookie(cookie);

            return idp;
        }

        private void SetContextCookie(string wctx, string wreply, string realm, string wsfedEndpoint)
        {
            var j = JObject.FromObject(new Context { Wctx = wctx, Wreply = wreply, Realm = realm, WsFedEndpoint = wsfedEndpoint });

            var cookie = new HttpCookie(_cookieContext, HttpUtility.UrlEncode(j.ToString()))
            {
                Secure = true,
                HttpOnly = true,
                Path = HttpRuntime.AppDomainAppVirtualPath
            };

            Response.Cookies.Add(cookie);
        }

        private Context GetContextCookie()
        {
            var cookie = Request.Cookies[_cookieContext];
            if (cookie == null)
            {
                throw new InvalidOperationException("cookie");
            }

            var json = JObject.Parse(HttpUtility.UrlDecode(cookie.Value));

            cookie.Value = "";
            cookie.Expires = new DateTime(2000, 1, 1);
            cookie.Path = HttpRuntime.AppDomainAppVirtualPath;
            Response.SetCookie(cookie);

            return json.ToObject<Context>();
        }

        private void SetOAuthContextCookie(OAuth2Context ctx)
        {
            var j = JObject.FromObject(ctx);

            var cookie = new HttpCookie(_cookieOAuthContext, HttpUtility.UrlEncode(j.ToString()));
            cookie.Secure = true;
            cookie.HttpOnly = true;
            cookie.Path = Request.ApplicationPath;

            Response.Cookies.Add(cookie);
        }

        private OAuth2Context GetOAuthContextCookie()
        {
            var cookie = Request.Cookies[_cookieOAuthContext];
            if (cookie == null)
            {
                throw new InvalidOperationException("cookie");
            }

            var json = JObject.Parse(HttpUtility.UrlDecode(cookie.Value));
            var data = json.ToObject<OAuth2Context>();

            var deletecookie = new HttpCookie(_cookieOAuthContext, ".");
            deletecookie.Secure = true;
            deletecookie.HttpOnly = true;
            deletecookie.Path = Request.ApplicationPath;
            Response.Cookies.Add(deletecookie);

            return data;
        }

        private void SetRememberHRDCookieValue(string realm)
        {
            var cookie = new HttpCookie(_cookieNameRememberHrd);
            if (String.IsNullOrWhiteSpace(realm))
            {
                realm = ".";
                cookie.Expires = DateTime.UtcNow.AddYears(-1);
            }
            else
            {
                cookie.Expires = DateTime.Now.AddMonths(1);
            }
            cookie.Value = realm;
            cookie.HttpOnly = true;
            cookie.Secure = true;
            cookie.Path = Request.ApplicationPath;
            Response.Cookies.Add(cookie);
        }

        private string GetRememberHRDCookieValue()
        {
            if (Request.Cookies.AllKeys.Contains(_cookieNameRememberHrd))
            {
                var cookie = Request.Cookies[_cookieNameRememberHrd];
                var realm = cookie.Value;
                var idps = GetVisibleIdentityProviders().Where(x => x.Name == realm);
                var idp = idps.SingleOrDefault();
                if (idp == null)
                {
                    Tracing.Verbose("Past HRD selection from cookie not found in current HRD list. Past value was: " + realm);
                    SetRememberHRDCookieValue(null);
                }

                return realm;
            }

            return null;
        }

        private ActionResult ProcessHomeRealmFromCookieValue(SignInRequestMessage message, string pastHRDSelection)
        {
            message.HomeRealm = pastHRDSelection;
            return ProcessSignInRequest(message);
        }

        internal class Context
        {
            public string Wctx { get; set; }
            public string Wreply { get; set; }
            public string Realm { get; set; }
            public string WsFedEndpoint { get; set; }
        }

        internal class OAuth2Context : Context
        {
            public int IdP { get; set; }
        }

        #endregion
    }
}
