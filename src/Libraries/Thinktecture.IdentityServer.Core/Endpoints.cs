/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;

namespace Thinktecture.IdentityServer
{
    /// <summary>
    /// Creates endpoint URIs for the various STS endpoints
    /// </summary>
    public class Endpoints
    {
        public Uri WSFederation { get; set; }
        public Uri WSFederationHRD { get; set; }
        public Uri WSFederationMetadata { get; set; }
        public Uri WSFederationRPMetadata { get; set; }
        public Uri WSTrustMex { get; set; }
        public Uri PrivacyNotice { get; set; }

        public Uri WSTrustMessageUserName { get; set; }
        public Uri WSTrustMixedUserName { get; set; }
        public Uri WSTrustMessageCertificate { get; set; }
        public Uri WSTrustMixedCertificate { get; set; }
        public Uri WSTrustMixedIssuedToken { get; set; }
        public Uri WSTrustMessageIssuedToken { get; set; }

        public Uri OidcAuthorize { get; set; }
        public Uri OidcToken { get; set; }
        public Uri OidcUserInfo { get; set; }

        public Uri SimpleHttp { get; set; }
        public Uri AdfsIntegration { get; set; }
        public Uri Wrap { get; set; }
        public Uri OAuth2Token { get; set; }
        public Uri OAuth2Callback { get; set; }
        public Uri OAuth2Authorize { get; set; }
        public Uri JSNotify { get; set; }

        public static class Paths
        {
            public const string WSFedIssuePage = "issue/wsfed";
            public const string WSFedHRD = "issue/hrd";
            public const string OAuth2Callback = "issue/hrd/oauth2callback";
            public const string WSFedHRDSelect = "issue/hrd/select";
            public const string WSFedHRDSignoutRedirect = "issue/hrd/SignoutRedirect";
            public const string WSFedMetadata = "FederationMetadata/2007-06/FederationMetadata.xml";
            public const string WSFedRPMetadata = "FederationMetadataRP/2007-06/FederationMetadata.xml";
            public const string PrivacyNotice = "privacyNotice.txt";
            public const string WSTrustBase = "issue/wstrust";
            public const string WSTrustFederationBase = "issue/federated/wstrust";
            public const string SimpleHttp = "issue/simple";
            public const string Wrap = "issue/wrap";
            public const string OAuth2Token = "issue/oauth2/token";
            public const string OAuth2Authorize = "issue/oauth2/authorize";
            public const string AdfsIntegration = "issue/adfs";
            public const string JSNotify = "issue/jsnotify";
            public const string Mex = "mex";
            public const string WSTrustMessageUserName = "message/username";
            public const string WSTrustMixedUserName = "mixed/username";
            public const string WSTrustMessageCertificate = "message/certificate";
            public const string WSTrustMixedCertificate = "mixed/certificate";
            public const string WSTrustMessageIssuedToken = "message/token";
            public const string WSTrustMixedIssuedToken = "mixed/token";

            public const string OidcAuthorize = "issue/oidc/authorize";
            public const string OidcToken = "issue/oidc/token";
            public const string OidcUserInfo = "issue/oidc/userinfo";

        }

        /// <summary>
        /// Creates the URIs based on the host header
        /// </summary>
        /// <returns>STS Endpoints</returns>
        public static Endpoints Create(string host, string applicationPath, int httpPort, int httpsPort)
        {
            return Create("https://" + host + applicationPath, httpPort, httpsPort);
        }

        /// <summary>
        /// Creates the URIs based on the baseUri.
        /// </summary>
        /// <param name="baseUri">The base URI.</param>
        /// <returns>STS Endpoints</returns>
        public static Endpoints Create(string baseUriString, int httpPort, int httpsPort)
        {
            var ep = new Endpoints();
            if (!baseUriString.EndsWith("/"))
            {
                baseUriString += "/";
            }
            
            // construct various http and https URIs
            var passive = new Uri(baseUriString + Paths.WSFedIssuePage);
            var builder = new UriBuilder(passive);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.WSFederation = builder.Uri;

            var hrd = new Uri(baseUriString + Paths.WSFedHRD);
            builder = new UriBuilder(hrd);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.WSFederationHRD = builder.Uri;

            // construct various http and https URIs
            var privacy = new Uri(baseUriString + Paths.PrivacyNotice);
            builder = new UriBuilder(privacy);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.PrivacyNotice = builder.Uri;

            var simpleHttp = new Uri(baseUriString + Paths.SimpleHttp);
            builder = new UriBuilder(simpleHttp);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.SimpleHttp = builder.Uri;

            var wrap = new Uri(baseUriString + Paths.Wrap);
            builder = new UriBuilder(wrap);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Wrap = builder.Uri;

            var oauth2token = new Uri(baseUriString + Paths.OAuth2Token);
            builder = new UriBuilder(oauth2token);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.OAuth2Token = builder.Uri;
            
            var oauth2callback = new Uri(baseUriString + Paths.OAuth2Callback);
            builder = new UriBuilder(oauth2callback);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.OAuth2Callback = builder.Uri;
            
            var oauth2auth = new Uri(baseUriString + Paths.OAuth2Authorize);
            builder = new UriBuilder(oauth2auth);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.OAuth2Authorize = builder.Uri;

            var oidcAuthorize = new Uri(baseUriString + Paths.OidcAuthorize);
            builder = new UriBuilder(oidcAuthorize);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.OidcAuthorize = builder.Uri;

            var oidcToken = new Uri(baseUriString + Paths.OidcToken);
            builder = new UriBuilder(oidcToken);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.OidcToken = builder.Uri;

            var oidcUserInfo = new Uri(baseUriString + Paths.OidcUserInfo);
            builder = new UriBuilder(oidcUserInfo);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.OidcUserInfo = builder.Uri;

            var jsnotify = new Uri(baseUriString + Paths.JSNotify);
            builder = new UriBuilder(jsnotify);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.JSNotify = builder.Uri;

            var wsfedmd = new Uri(baseUriString + Paths.WSFedMetadata);
            builder = new UriBuilder(wsfedmd);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.WSFederationMetadata = builder.Uri;

            var wsfedrpmd = new Uri(baseUriString + Paths.WSFedRPMetadata);
            builder = new UriBuilder(wsfedrpmd);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.WSFederationRPMetadata = builder.Uri;
            
            var adfs = new Uri(baseUriString + Paths.AdfsIntegration);
            builder = new UriBuilder(adfs);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.AdfsIntegration = builder.Uri;

            var activeClear = new Uri(baseUriString + Paths.WSTrustBase);
            builder = new UriBuilder(activeClear);
            builder.Scheme = Uri.UriSchemeHttp;
            builder.Port = httpPort;
            activeClear = builder.Uri;

            builder = new UriBuilder(activeClear);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            var activeSsl = builder.Uri;

            var activeFederatedClear = new Uri(baseUriString + Paths.WSTrustFederationBase);
            builder = new UriBuilder(activeFederatedClear);
            builder.Scheme = Uri.UriSchemeHttp;
            builder.Port = httpPort;
            activeFederatedClear = builder.Uri;

            builder = new UriBuilder(activeFederatedClear);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            var activeFederatedSsl = builder.Uri;

            ep.WSTrustMessageUserName = new Uri(activeClear + "/" + Paths.WSTrustMessageUserName);
            ep.WSTrustMixedUserName = new Uri(activeSsl + "/" + Paths.WSTrustMixedUserName);

            ep.WSTrustMessageCertificate = new Uri(activeClear + "/" + Paths.WSTrustMessageCertificate);
            ep.WSTrustMixedCertificate = new Uri(activeSsl + "/" + Paths.WSTrustMixedCertificate);

            ep.WSTrustMessageIssuedToken = new Uri(activeFederatedClear + "/" + Paths.WSTrustMessageIssuedToken);
            ep.WSTrustMixedIssuedToken = new Uri(activeFederatedSsl + "/" + Paths.WSTrustMixedIssuedToken);

            ep.WSTrustMex = new Uri(activeSsl + "/" + Paths.Mex);

            return ep;
        }
    }
}