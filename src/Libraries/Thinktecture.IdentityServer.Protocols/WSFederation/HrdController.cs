/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.IO;
using System.IdentityModel.Services.Configuration;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using BrockAllen.OAuth2;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.Saml2;
using Microsoft.IdentityModel.Protocols.Saml2.Constants;
using Microsoft.IdentityModel.Protocols.WSFederation.Metadata;
using Microsoft.IdentityModel.SecurityTokenService;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;
using Lifetime = Microsoft.IdentityModel.Protocols.WSTrust.Lifetime;
using RequestSecurityTokenResponse = Microsoft.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse;
using RequestedSecurityToken = Microsoft.IdentityModel.Protocols.WSTrust.RequestedSecurityToken;
using Claim = System.Security.Claims.Claim;
using ClaimTypes = System.Security.Claims.ClaimTypes;
using ClaimValueTypes = System.Security.Claims.ClaimValueTypes;
using ClaimsIdentity = System.Security.Claims.ClaimsIdentity;
using ClaimsPrincipal = System.Security.Claims.ClaimsPrincipal;
using FederatedAuthentication = Microsoft.IdentityModel.Web.FederatedAuthentication;

namespace Thinktecture.IdentityServer.Protocols.WSFederation
{
    public class HrdController : Controller
    {
        const string _cookieName = "hrdsignout";
        const string _cookieNameRememberHrd = "hrdSelection";
        const string _cookieContext = "idsrvcontext";

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

        public ActionResult Issue()
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
                return ProcessSignOut(signoutMessage);
            }

            return View("Error");
        }

        [HttpPost]
        [ActionName("Issue")]
        public ActionResult IssueResponse()
        {
            if (Request.Form.HasKeys())
            {
                if (Request.Form["SAMLResponse"] != null)
                {
                    var samlResponse = Request.Form["SAMLResponse"];
                    var responseDecoded = Encoding.UTF8.GetString(Convert.FromBase64String(HttpUtility.HtmlDecode(samlResponse)));

                    Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken token;

                    using (var sr = new StringReader(responseDecoded))
                    {
                        using (var reader = XmlReader.Create(sr))
                        {
                            reader.ReadToFollowing("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion");

                            var coll = Microsoft.IdentityModel.Tokens.SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();

                            token = (Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityToken)coll.ReadToken(reader.ReadSubtree());

                        }
                    }

                    var realm = token.Assertion.Conditions.AudienceRestrictions[0].Audiences[0].ToString();
                    var issuer = token.Assertion.Issuer.Value;

                    var rstr = new RequestSecurityTokenResponse
                                   {
                                       TokenType = Constants.TokenKeys.TokenType,
                                       RequestType = Constants.TokenKeys.RequestType,
                                       KeyType = Constants.TokenKeys.KeyType,
                                       Lifetime = new Lifetime(token.Assertion.IssueInstant, token.Assertion.Conditions.NotOnOrAfter),
                                       AppliesTo = new System.ServiceModel.EndpointAddress(new Uri(realm)),
                                       RequestedSecurityToken = new RequestedSecurityToken(GetElement(responseDecoded))
                                   };

                    var principal = GetClaimsIdentity(rstr);
                    if (principal != null)
                    {
                        var claimsPrinciple = Microsoft.IdentityModel.Claims.ClaimsPrincipal.CreateFromPrincipal(principal);

                        var requestMessage = new Microsoft.IdentityModel.Protocols.WSFederation.SignInRequestMessage(new Uri("http://foo"), realm);
                        var ipc = new SamlTokenServiceConfiguration(issuer);
                        SecurityTokenService identityProvider = new SamlTokenService(ipc);



                        var responseMessage = Microsoft.IdentityModel.Web.FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, claimsPrinciple, identityProvider);

                        new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime).AddEndpoint(responseMessage.BaseUri.AbsoluteUri);
                        Microsoft.IdentityModel.Web.FederatedPassiveSecurityTokenServiceOperations.ProcessSignInResponse(responseMessage, System.Web.HttpContext.Current.Response);
                    }
                    //return new EmptyResult();

                }
                var fam = new WSFederationAuthenticationModule { FederationConfiguration = new FederationConfiguration() };

                if (fam.CanReadSignInResponse(Request))
                {
                    var responseMessage = fam.GetSignInResponseMessage(Request);
                    return ProcessSignInResponse(responseMessage, fam.GetSecurityToken(Request));
                }
            }


            return View("Error");
        }

        #region SAML2 Helper
        private static XmlElement GetElement(string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc.DocumentElement;
        }
        public static XElement ToXElement(XmlElement xml)
        {
            var doc = new XmlDocument();

            doc.AppendChild(doc.ImportNode(xml, true));

            return XElement.Parse(doc.InnerXml);

        }
    
        private static IClaimsPrincipal GetClaimsIdentity(RequestSecurityTokenResponse rstr)
        {
            var rstrXml = rstr.RequestedSecurityToken.SecurityTokenXml;

            var xnm = new XmlNamespaceManager(rstrXml.OwnerDocument.NameTable);

            xnm.AddNamespace(Microsoft.IdentityModel.Tokens.Saml2.Saml2Constants.Prefix, Microsoft.IdentityModel.Tokens.Saml2.Saml2Constants.Namespace);

            XNamespace ast = "urn:oasis:names:tc:SAML:2.0:assertion";
            var xElement = ToXElement(rstrXml);

            var xAssertionElement = xElement.Element(ast + "Assertion");
            if (xAssertionElement != null)
            {
                var xAttributeStatement = xAssertionElement.Element(ast + "AttributeStatement");
                if (xAttributeStatement != null)
                {
                    var xAttributes = xAttributeStatement.Elements(ast + "Attribute");
                    IClaimsIdentity claimsIdentity = new Microsoft.IdentityModel.Claims.ClaimsIdentity();
                    foreach (var element in xAttributes)
                    {
                        var claimType = element.Attribute("NameFormat") + "/" + element.Attribute("Name");
                        var value = element.Value;

                        var xAttribute = element.Attribute("Name");
                        if (xAttribute != null && xAttribute.Value == "urn:FirstName")
                            claimsIdentity.Claims.Add(new Microsoft.IdentityModel.Claims.Claim(ClaimTypes.Name, element.Value));
                        claimsIdentity.Claims.Add(new Microsoft.IdentityModel.Claims.Claim(claimType, value ?? ""));
                    }
                    var claimsIdentitycol = new ClaimsIdentityCollection(new[] { claimsIdentity });
                    return Microsoft.IdentityModel.Claims.ClaimsPrincipal.CreateFromIdentities(claimsIdentitycol);
                }
            }
            return null;
        }
        #endregion

        #region Helper

        private ActionResult ProcessSignInRequest(SignInRequestMessage message)
        {
            if (!string.IsNullOrWhiteSpace(message.HomeRealm))
            {
                return RedirectToIdentityProvider(message);
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
        }

        private ActionResult ProcessHomeRealmFromCookieValue(SignInRequestMessage message, string pastHRDSelection)
        {
            message.HomeRealm = pastHRDSelection;
            return ProcessSignInRequest(message);
        }

        private ActionResult ProcessSignOut(SignOutRequestMessage message)
        {
            // check for return url
            if (!string.IsNullOrWhiteSpace(message.Reply))
            {
                ViewBag.ReturnUrl = message.Reply;
            }

            // check for existing sign in sessions
            var mgr = new SignInSessionsManager(HttpContext, _cookieName);
            var realms = mgr.GetEndpoints();
            mgr.ClearEndpoints();
            //System.IdentityModel.Services.FederatedAuthentication.SessionAuthenticationModule.SignOut();
            //System.IdentityModel.Services.FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            //System.IdentityModel.Services.FederatedAuthentication.WSFederationAuthenticationModule.SignOut();
            return View("Signout", realms);
        }

        private ActionResult ProcessSignInResponse(SignInResponseMessage responseMessage, SecurityToken token)
        {
            var principal = ValidateToken(token);
            var issuerName = principal.Claims.First().Issuer;

            principal.Identities.First().AddClaim(new Claim(Constants.Claims.IdentityProvider, issuerName, ClaimValueTypes.String, Constants.InternalIssuer));

            var context = GetContextCookie();
            var message = new SignInRequestMessage(new Uri("http://foo"), context.Realm);
            message.Context = context.Wctx;

            // issue token and create ws-fed response
            var wsFedResponse = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                message,
                principal,
                TokenServiceConfiguration.Current.CreateSecurityTokenService());

            // set cookie for single-sign-out
            new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime)
                .SetEndpoint(context.WsFedEndpoint);

            return new WSFederationResult(wsFedResponse, requireSsl: ConfigurationRepository.WSFederation.RequireSslForReplyTo);
        }

        IEnumerable<IdentityProvider> GetEnabledWSIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.Type == IdentityProviderTypes.WSStar);
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
                return RedirectToIdentityProvider(ip, message);
            }
            else
            {
                Tracing.Verbose("HRD selection screen displayed.");
                var vm = new HrdViewModel(message, idps);
                return View("HRD", vm);
            }
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
                    return RedirectToIdentityProvider(ip, signinMessage);
                }

                if (ip.Type == IdentityProviderTypes.OAuth2)
                {
                    return ProcessOAuth2SignIn(ip, signinMessage);
                }
                if (ip.Type == IdentityProviderTypes.Saml2)
                {
                    return ProcessSaml2SignIn(ip, signinMessage);
                }
            }
            catch (Exception ex)
            {
                Tracing.Error(ex.ToString());
            }

            return View("Error");
        }

        private ActionResult ProcessSaml2SignIn(IdentityProvider ip, SignInRequestMessage request)
        {
            if (ip.Enabled)
            {
                var saml2ProtocolSerializer = new Saml2ProtocolSerializer();
                var protocolBinding = ProtocolBindings.HttpRedirect;
                HttpBindingSerializer httpBindingSerializer = new HttpRedirectBindingSerializer(saml2ProtocolSerializer);
                var authenticationRequest = new AuthenticationRequest()
                                                {
                                                    Issuer =
                                                        new Microsoft.IdentityModel.Tokens.Saml2.Saml2NameIdentifier(request.Realm.TrimEnd('/'), new Uri(ip.WSFederationEndpoint)),
                                                    Destination = new Uri(ip.WSFederationEndpoint)
                                                };

                var messageContainer = new MessageContainer(authenticationRequest, new ProtocolEndpoint(protocolBinding, new Uri(ip.WSFederationEndpoint + "/signon.ashx")));
                var httpMessage = httpBindingSerializer.Serialize(messageContainer);
                httpBindingSerializer.WriteHttpMessage(new HttpResponseWrapper(System.Web.HttpContext.Current.Response), httpMessage);
                ControllerContext.HttpContext.ApplicationInstance.CompleteRequest();
                // return new EmptyResult();
            }
            return View("Error");
        }

        private ActionResult RedirectToIdentityProvider(SignInRequestMessage request)
        {
            IdentityProvider idp = null;
            if (IdentityProviderRepository.TryGet(request.HomeRealm, out idp) && idp.Enabled)
            {
                return RedirectToIdentityProvider(idp, request);
            }

            return View("Error");
        }

        private ActionResult RedirectToIdentityProvider(IdentityProvider identityProvider, SignInRequestMessage request)
        {
            var message = new SignInRequestMessage(new Uri(identityProvider.WSFederationEndpoint), ConfigurationRepository.Global.IssuerUri);
            SetContextCookie(request.Context, request.Realm, identityProvider.WSFederationEndpoint);

            return new RedirectResult(message.WriteQueryString());
        }

        private void SetContextCookie(string wctx, string realm, string wsfedEndpoint)
        {
            var j = JObject.FromObject(new Context { Wctx = wctx, Realm = realm, WsFedEndpoint = wsfedEndpoint });

            var cookie = new HttpCookie(_cookieContext, j.ToString())
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

        internal class Context
        {
            public string Wctx { get; set; }
            public string Realm { get; set; }
            public string WsFedEndpoint { get; set; }
        }

        internal class OAuth2Context : Context
        {
            public int IdP { get; set; }
        }

        private void SetOAuthContextCookie(OAuth2Context ctx)
        {
            var j = JObject.FromObject(ctx);

            var cookie = new HttpCookie("idsrvoauthcontext", j.ToString());
            cookie.Secure = true;
            cookie.HttpOnly = true;
            cookie.Path = Request.ApplicationPath;

            Response.Cookies.Add(cookie);
        }

        private OAuth2Context GetOAuthContextCookie()
        {
            var cookie = Request.Cookies["idsrvoauthcontext"];
            if (cookie == null)
            {
                throw new InvalidOperationException("cookie");
            }

            var json = JObject.Parse(HttpUtility.UrlDecode(cookie.Value));
            var data = json.ToObject<OAuth2Context>();

            var deletecookie = new HttpCookie("idsrvoauthcontext", ".");
            deletecookie.Secure = true;
            deletecookie.HttpOnly = true;
            deletecookie.Path = Request.ApplicationPath;
            Response.Cookies.Add(deletecookie);

            return data;
        }

        private ActionResult ProcessOAuth2SignIn(IdentityProvider ip, SignInRequestMessage request)
        {
            var ctx = new OAuth2Context
            {
                Wctx = request.Context,
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
            }

            return View("Error");
        }

        ProviderType GetProviderTypeFromOAuthProfileTypes(OAuth2ProviderTypes type)
        {
            switch (type)
            {
                case OAuth2ProviderTypes.Facebook: return ProviderType.Facebook;
                case OAuth2ProviderTypes.Live: return ProviderType.Live;
                case OAuth2ProviderTypes.Google: return ProviderType.Google;
                default: throw new Exception("Invalid OAuthProfileTypes");
            }
        }

        [HttpGet]
        public async Task<ActionResult> OAuthTokenCallback()
        {
            var ctx = GetOAuthContextCookie();
            var ip = GetVisibleIdentityProviders().Single(x => x.ID == ctx.IdP);

            var oauth2 = new OAuth2Client(GetProviderTypeFromOAuthProfileTypes(ip.ProviderType.Value), ip.ClientID, ip.ClientSecret);
            var result = await oauth2.ProcessCallbackAsync();
            if (result.Error != null) return View("Error");

            var claims = result.Claims.ToList();
            string[] claimsToRemove = new string[]
            {
                "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider",
                ClaimTypes.AuthenticationInstant
            };
            foreach (var toRemove in claimsToRemove)
            {
                var tmp = claims.Find(x => x.Type == toRemove);
                if (tmp != null) claims.Remove(tmp);
            }
            claims.Add(new Claim(Constants.Claims.IdentityProvider, ip.Name, ClaimValueTypes.String, Constants.InternalIssuer));
            var id = new ClaimsIdentity(claims, "OAuth");
            var cp = new ClaimsPrincipal(id);
            return ProcessOAuthResponse(cp, ctx);
        }

        private ActionResult ProcessOAuthResponse(ClaimsPrincipal principal, Context context)
        {
            var message = new SignInRequestMessage(new Uri("http://foo"), context.Realm);
            message.Context = context.Wctx;

            // issue token and create ws-fed response
            var wsFedResponse = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                message,
                principal,
                TokenServiceConfiguration.Current.CreateSecurityTokenService());

            // set cookie for single-sign-out
            new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime)
                .SetEndpoint(context.WsFedEndpoint);

            return new WSFederationResult(wsFedResponse, requireSsl: ConfigurationRepository.WSFederation.RequireSslForReplyTo);
        }

        #endregion
    }
}
