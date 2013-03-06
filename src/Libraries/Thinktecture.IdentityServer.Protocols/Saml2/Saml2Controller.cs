using System;
using System.ComponentModel.Composition;
using System.IO;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using System.Xml.Linq;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.Saml2;
using Microsoft.IdentityModel.Protocols.Saml2.Constants;
using Microsoft.IdentityModel.Protocols.WSFederation;
using Microsoft.IdentityModel.Protocols.WSFederation.Metadata;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;
using ClaimTypes = System.Security.Claims.ClaimTypes;

namespace Thinktecture.IdentityServer.Protocols.Saml2
{
    [ClaimsAuthorize(Constants.Actions.Issue, Constants.Resources.WSFederation)]
    public class Saml2Controller : Controller
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IIdentityProviderRepository IdentityProviderRepository { get; set; }


        public Saml2Controller()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public Saml2Controller(IConfigurationRepository configurationRepository, IIdentityProviderRepository identityProviderRepository)
        {
            IdentityProviderRepository = identityProviderRepository;
            ConfigurationRepository = configurationRepository;
        }

        /// <summary>
        /// Process Saml2 request
        /// </summary>
        /// <returns></returns>
        public ActionResult Issue()
        {
            Tracing.Verbose("HRD endpoint called.");

            var message = WSFederationMessage.CreateFromUri(HttpContext.Request.Url);

            var signinMessage = message as SignInRequestMessage;
            if (signinMessage != null)
            {
                IdentityProvider idp;
                //hardcoded for testing purpose
                IdentityProviderRepository.TryGet("OIOSAML", out idp);

                if (idp == null) return View("Error");

                try
                {
                    if (idp.Type == IdentityProviderTypes.Saml2)
                    {
                        return ProcessSaml2SignIn(idp, signinMessage);
                    }
                }
                catch (Exception ex)
                {
                    Tracing.Error(ex.ToString());
                }
            } return View("Error");
        }


        /// <summary>
        /// Process Saml2 sigin Request 
        /// </summary>
        /// <param name="ip"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        private ActionResult ProcessSaml2SignIn(IdentityProvider ip, SignInRequestMessage request)
        {
            if (ip.Enabled)
            {
                var saml2ProtocolSerializer = new Saml2ProtocolSerializer();
                var protocolBinding = ProtocolBindings.HttpRedirect;
                HttpBindingSerializer httpBindingSerializer = new HttpRedirectBindingSerializer(saml2ProtocolSerializer);
                var authenticationRequest = new AuthenticationRequest
                                                {
                                                    Issuer = new Microsoft.IdentityModel.Tokens.Saml2.Saml2NameIdentifier(request.Realm.TrimEnd('/'), new Uri(ip.WSFederationEndpoint)),
                                                    Destination = new Uri(ip.WSFederationEndpoint)
                                                };

                //Provide Service provider default signin home page - hardcoded for testing purpose
                var messageContainer = new MessageContainer(authenticationRequest, new ProtocolEndpoint(protocolBinding, new Uri(ip.WSFederationEndpoint + "/signon.ashx")));
                var httpMessage = httpBindingSerializer.Serialize(messageContainer);
                httpBindingSerializer.WriteHttpMessage(new HttpResponseWrapper(System.Web.HttpContext.Current.Response), httpMessage);
                ControllerContext.HttpContext.ApplicationInstance.CompleteRequest();
            }
            return View("Error");
        }

        /// <summary>
        /// Process Saml2 signon response
        /// </summary>
        /// <returns></returns>
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
                        var claimsPrinciple = ClaimsPrincipal.CreateFromPrincipal(principal);
                        var requestMessage = new SignInRequestMessage(new Uri("http://foo"), realm);
                        var ipc = new SamlTokenServiceConfiguration(issuer);
                        SecurityTokenService identityProvider = new SamlTokenService(ipc);
                        var responseMessage = Microsoft.IdentityModel.Web.FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, claimsPrinciple, identityProvider);
                        Microsoft.IdentityModel.Web.FederatedPassiveSecurityTokenServiceOperations.ProcessSignInResponse(responseMessage, System.Web.HttpContext.Current.Response);
                    }
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

        /// <summary>
        /// Get Claims Principal from incoming response.
        /// </summary>
        /// <param name="rstr"></param>
        /// <returns></returns>
        private static IClaimsPrincipal GetClaimsIdentity(RequestSecurityTokenResponse rstr)
        {
            var rstrXml = rstr.RequestedSecurityToken.SecurityTokenXml;

            if (rstrXml.OwnerDocument != null)
            {
                var xnm = new XmlNamespaceManager(rstrXml.OwnerDocument.NameTable);

                xnm.AddNamespace(Microsoft.IdentityModel.Tokens.Saml2.Saml2Constants.Prefix, Microsoft.IdentityModel.Tokens.Saml2.Saml2Constants.Namespace);
            }

            XNamespace ast = "urn:oasis:names:tc:SAML:2.0:assertion";
            var xElement = ToXElement(rstrXml);

            var xElement1 = xElement.Element(ast + "Assertion");
            if (xElement1 != null)
            {
                var attributeStatement1 = xElement1.Element(ast + "AttributeStatement");
                if (attributeStatement1 != null)
                {
                    var attributes1 = attributeStatement1.Elements(ast + "Attribute");
                    IClaimsIdentity claimsIdentity1 = new ClaimsIdentity();
                    foreach (var element in attributes1)
                    {
                        var claimType = element.Attribute("NameFormat") + "/" + element.Attribute("Name");
                        var value = element.Value;

                        var xAttribute = element.Attribute("Name");
                        if (xAttribute != null && xAttribute.Value == "urn:FirstName")
                            claimsIdentity1.Claims.Add(new Claim(ClaimTypes.Name, element.Value));
                        claimsIdentity1.Claims.Add(new Claim(claimType, value));
                    }
                    var claimsIdentitycol = new ClaimsIdentityCollection(new[] { claimsIdentity1 });
                    return ClaimsPrincipal.CreateFromIdentities(claimsIdentitycol);
                }
            }
            return null;
        }
        #endregion
    }
}
