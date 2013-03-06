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
        public Uri WSSAML2 { get; set; }
        public Uri WSFederationHRD { get; set; }
        public Uri WSFederationMetadata { get; set; }
        public Uri Saml2Metadata { get; set; }

        public Uri Saml2SLORedirect { get; set; }
        public Uri Saml2SLOPOST { get; set; }
        public Uri Saml2SLORedirectResponse { get; set; }
        public Uri Saml2SLOPostResponse { get; set; }

        public Uri Saml2ASTRedirect { get; set; }
        public Uri Saml2ASTPost { get; set; }
        public Uri Saml2ASTArtifact { get; set; }

        public Uri WSTrustMex { get; set; }
        public Uri PrivacyNotice { get; set; }

        public Uri WSTrustMessageUserName { get; set; }
        public Uri WSTrustMixedUserName { get; set; }
        public Uri WSTrustMessageCertificate { get; set; }
        public Uri WSTrustMixedCertificate { get; set; }
        
        public Uri SimpleHttp { get; set; }
        public Uri Wrap { get; set; }
        public Uri OAuth2Token { get; set; }
        public Uri OAuth2Callback { get; set; }
        public Uri OAuth2Authorize { get; set; }
        public Uri JSNotify { get; set; }

        public static class Paths
        {
            public const string WSFedIssuePage = "issue/wsfed";
            public const string WSSaml2Page = "issue/saml2";
            public const string WSFedHRD = "issue/hrd";
            public const string WSFedHRDSelect = "issue/hrd/select";
            public const string WSFedMetadata = "FederationMetadata/2007-06/FederationMetadata.xml";
            public const string Saml2Metadata = "Saml2Metadata/2007-06/Saml2Metadata.xml";

            public const string Saml2SLORedirect = "saml/redirect/slo";
            public const string Saml2SLOPOST = "saml/post/slo";
            public const string Saml2SLORedirectResponse = "saml/redirect/sloresponse";
            public const string Saml2SLOPostResponse = "saml/post/sloresponse";


            public const string Saml2ASTRedirect = "saml/redirect/ac";
            public const string Saml2ASTPost = "saml/post/ac";
            public const string Saml2ASTArtifact = "saml/artifact/ac";
            


            public const string PrivacyNotice = "privacyNotice.txt";
            public const string WSTrustBase = "issue/wstrust";
            public const string SimpleHttp = "issue/simple";
            public const string Wrap = "issue/wrap";
            public const string OAuth2Token = "issue/oauth2/token";
            public const string OAuth2Callback = "issue/oauth2/callback";
            public const string OAuth2Authorize = "issue/oauth2/authorize";
            public const string JSNotify = "issue/jsnotify";
            public const string Mex = "mex";
            public const string WSTrustMessageUserName = "message/username";
            public const string WSTrustMixedUserName = "mixed/username";
            public const string WSTrustMessageCertificate = "message/certificate";
            public const string WSTrustMixedCertificate = "mixed/certificate";
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

            var saml = new Uri(baseUriString + Paths.WSSaml2Page);
            builder = new UriBuilder(saml);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.WSSAML2 = builder.Uri;

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

            var saml2pmd = new Uri(baseUriString + Paths.Saml2Metadata);
            builder = new UriBuilder(saml2pmd);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2Metadata = builder.Uri;

            //
            var saml2psloredirect= new Uri(baseUriString + Paths.Saml2SLORedirect);
            builder = new UriBuilder(saml2psloredirect);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2SLORedirect = builder.Uri;

            var saml2psloredirectresponse = new Uri(baseUriString + Paths.Saml2SLORedirectResponse);
            builder = new UriBuilder(saml2psloredirectresponse);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2SLORedirectResponse = builder.Uri;

            var saml2pslopostresponse = new Uri(baseUriString + Paths.Saml2SLOPostResponse);
            builder = new UriBuilder(saml2pslopostresponse);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2SLOPostResponse = builder.Uri;

            var saml2pslopost = new Uri(baseUriString + Paths.Saml2SLOPOST);
            builder = new UriBuilder(saml2pslopost);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2SLOPOST = builder.Uri;

            var saml2pastredirect  = new Uri(baseUriString + Paths.Saml2ASTRedirect);
            builder = new UriBuilder(saml2pastredirect);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2ASTRedirect = builder.Uri;

            var saml2pastpost  = new Uri(baseUriString + Paths.Saml2ASTPost);
            builder = new UriBuilder(saml2pastpost);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2ASTPost = builder.Uri;

            var saml2partifact  = new Uri(baseUriString + Paths.Saml2ASTArtifact);
            builder = new UriBuilder(saml2partifact);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            ep.Saml2ASTArtifact = builder.Uri;
            //

            var activeClear = new Uri(baseUriString + Paths.WSTrustBase);
            builder = new UriBuilder(activeClear);
            builder.Scheme = Uri.UriSchemeHttp;
            builder.Port = httpPort;
            activeClear = builder.Uri;

            builder = new UriBuilder(activeClear);
            builder.Scheme = Uri.UriSchemeHttps;
            builder.Port = httpsPort;
            var activeSsl = builder.Uri;

            ep.WSTrustMessageUserName = new Uri(activeClear, Paths.WSTrustMessageUserName);
            ep.WSTrustMixedUserName = new Uri(activeSsl, Paths.WSTrustMixedUserName);

            ep.WSTrustMessageCertificate = new Uri(activeClear, Paths.WSTrustMessageCertificate);
            ep.WSTrustMixedCertificate = new Uri(activeSsl, Paths.WSTrustMixedCertificate);

            ep.WSTrustMex = new Uri(activeSsl, Paths.Mex);

            return ep;
        }
    }
}