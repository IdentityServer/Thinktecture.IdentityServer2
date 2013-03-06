/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Web.Mvc;
using System.Web.WebPages;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web.Controllers
{
    public class HomeController : Controller
    {
        [Import]
        public IConfigurationRepository Configuration { get; set; }

        public HomeController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public HomeController(IConfigurationRepository configuration)
        {
            Configuration = configuration;
        }

        public ActionResult Index()
        {
            if (Request.Browser.IsMobileDevice)
            {
                HttpContext.SetOverriddenBrowser(BrowserOverride.Desktop);
            }

            return View();
        }

        public ActionResult AppIntegration()
        {
            var endpoints = Endpoints.Create(
                               HttpContext.Request.Headers["Host"],
                               HttpContext.Request.ApplicationPath,
                               Configuration.Global.HttpPort,
                               Configuration.Global.HttpsPort);

            var list = new Dictionary<string, string>();

            // federation metadata
            if (Configuration.FederationMetadata.Enabled)
            {
                list.Add("WS-Federation metadata", endpoints.WSFederationMetadata.AbsoluteUri);
            }

            // saml2 metadata
            if (Configuration.Saml2Metadata.Enabled)
            {
                list.Add("SAML2 Protocol metadata", endpoints.Saml2Metadata.AbsoluteUri);
            }

            // ws-federation
            if (Configuration.WSFederation.Enabled)
            {
                if (Configuration.WSFederation.EnableAuthentication)
                {
                    list.Add("WS-Federation", endpoints.WSFederation.AbsoluteUri);
                }
                if (Configuration.WSFederation.EnableFederation)
                {
                    list.Add("WS-Federation HRD", endpoints.WSFederationHRD.AbsoluteUri);
                }
            }

            // saml2
            if(Configuration.Saml2.Enabled)
            {
                if(Configuration.Saml2.EnableAuthentication)
                {
                    list.Add("Saml2", endpoints.WSSAML2.AbsoluteUri);
                }
            }

            // ws-trust
            if (Configuration.WSTrust.Enabled)
            {
                list.Add("WS-Trust metadata", endpoints.WSTrustMex.AbsoluteUri);

                if (Configuration.WSTrust.EnableMessageSecurity)
                {
                    list.Add("WS-Trust message security (user name)", endpoints.WSTrustMessageUserName.AbsoluteUri);

                    if (Configuration.WSTrust.EnableClientCertificateAuthentication)
                    {
                        list.Add("WS-Trust message security (client certificate)", endpoints.WSTrustMessageCertificate.AbsoluteUri);
                    }
                }

                if (Configuration.WSTrust.EnableMixedModeSecurity)
                {
                    list.Add("WS-Trust mixed mode security (user name)", endpoints.WSTrustMixedUserName.AbsoluteUri);

                    if (Configuration.WSTrust.EnableClientCertificateAuthentication)
                    {
                        list.Add("WS-Trust mixed mode security (client certificate)", endpoints.WSTrustMixedCertificate.AbsoluteUri);
                    }
                }
            }

            // oauth2
            if (Configuration.OAuth2.Enabled)
            {
                if (Configuration.OAuth2.EnableImplicitFlow)
                {
                    list.Add("OAuth2 Authorize", endpoints.OAuth2Authorize.AbsoluteUri);
                }
                list.Add("OAuth2 Callback", endpoints.OAuth2Callback.AbsoluteUri);
                if (Configuration.OAuth2.EnableResourceOwnerFlow)
                {
                    list.Add("OAuth2 Token", endpoints.OAuth2Token.AbsoluteUri);
                }
            }

            // simple http
            if (Configuration.SimpleHttp.Enabled)
            {
                list.Add("Simple HTTP", endpoints.SimpleHttp.AbsoluteUri);
            }

            return View(list);
        }
    }
}
