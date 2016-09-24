/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
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
            var host = Configuration.Global.PublicHostName;
            if (String.IsNullOrWhiteSpace(host))
            {
                host = HttpContext.Request.Headers["Host"];
            }
            var endpoints = Endpoints.Create(
                               host,
                               HttpContext.Request.ApplicationPath,
                               Configuration.Global.HttpPort,
                               Configuration.Global.HttpsPort);

            var list = new Dictionary<string, string>();

            // federation metadata
            if (Configuration.FederationMetadata.Enabled)
            {
                list.Add("WS-Federation metadata", endpoints.WSFederationMetadata.AbsoluteUri);
                list.Add("WS-Federation metadata (RP)", endpoints.WSFederationRPMetadata.AbsoluteUri);
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
                    list.Add("OAuth2 Callback", endpoints.OAuth2Callback.AbsoluteUri);
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

                    if (Configuration.WSTrust.EnableFederatedAuthentication) {
                        list.Add("WS-Trust message security (federation)", endpoints.WSTrustMessageIssuedToken.AbsoluteUri);
                    }
                }

                if (Configuration.WSTrust.EnableMixedModeSecurity)
                {
                    list.Add("WS-Trust mixed mode security (user name)", endpoints.WSTrustMixedUserName.AbsoluteUri);

                    if (Configuration.WSTrust.EnableClientCertificateAuthentication)
                    {
                        list.Add("WS-Trust mixed mode security (client certificate)", endpoints.WSTrustMixedCertificate.AbsoluteUri);
                    }

                    if (Configuration.WSTrust.EnableFederatedAuthentication)
                    {
                        list.Add("WS-Trust mixed mode security (federation)", endpoints.WSTrustMixedIssuedToken.AbsoluteUri);
                    }
                }
            }

            // openid connect
            if (Configuration.OpenIdConnect.Enabled)
            {
                list.Add("OpenID Connect Authorize", endpoints.OidcAuthorize.AbsoluteUri);
                list.Add("OpenID Connect Token", endpoints.OidcToken.AbsoluteUri);
                list.Add("OpenID Connect UserInfo", endpoints.OidcUserInfo.AbsoluteUri);
            }

            // oauth2
            if (Configuration.OAuth2.Enabled)
            {
                if (Configuration.OAuth2.EnableImplicitFlow)
                {
                    list.Add("OAuth2 Authorize", endpoints.OAuth2Authorize.AbsoluteUri);
                }
                if (Configuration.OAuth2.EnableResourceOwnerFlow)
                {
                    list.Add("OAuth2 Token", endpoints.OAuth2Token.AbsoluteUri);
                }
            }

            // adfs integration
            if (Configuration.AdfsIntegration.Enabled)
            {
                if (Configuration.AdfsIntegration.UsernameAuthenticationEnabled || 
                    Configuration.AdfsIntegration.SamlAuthenticationEnabled || 
                    Configuration.AdfsIntegration.JwtAuthenticationEnabled)
                {
                    list.Add("ADFS Integration", endpoints.AdfsIntegration.AbsoluteUri);
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
