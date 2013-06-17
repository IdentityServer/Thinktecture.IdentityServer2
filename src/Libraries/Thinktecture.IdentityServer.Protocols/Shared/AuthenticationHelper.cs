/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols
{
    public class AuthenticationHelper
    {
        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IRelyingPartyRepository RelyingPartyRepository { get; set; }

        public AuthenticationHelper()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public AuthenticationHelper(IUserRepository userRepository, IRelyingPartyRepository relyingPartyRepository)
        {
            UserRepository = userRepository;
            RelyingPartyRepository = relyingPartyRepository;
        }

        public bool TryGetPrincipalFromHttpRequest(HttpRequestBase request, out ClaimsPrincipal principal)
        {
            principal = null;

            // first check for client certificate
            if (TryGetClientCertificatePrincipalFromRequest(request, out principal))
            {
                return true;
            }

            // then basic authentication
            if (TryGetBasicAuthenticationPrincipalFromRequest(request, out principal))
            {
                return true;
            }

            return false;
        }

        public bool TryGetPrincipalFromHttpRequest(HttpRequestMessage request, out ClaimsPrincipal principal)
        {
            principal = null;

            // first check for client certificate
            if (TryGetClientCertificatePrincipalFromRequest(request, out principal))
            {
                return true;
            }

            // then basic authentication
            if (TryGetBasicAuthenticationPrincipalFromRequest(request, out principal))
            {
                return true;
            }

            return false;
        }

        #region Client Certificates
        public bool TryGetClientCertificatePrincipalFromRequest(HttpRequestBase request, out ClaimsPrincipal principal)
        {
            X509Certificate2 clientCertificate = null;
            principal = null;

            if (TryGetClientCertificateFromRequest(request, out clientCertificate))
            {
                string userName;
                if (UserRepository.ValidateUser(clientCertificate, out userName))
                {
                    principal = CreatePrincipal(userName, AuthenticationMethods.X509);
                    return true;
                }
            }

            return false;
        }

        public bool TryGetClientCertificatePrincipalFromRequest(HttpRequestMessage request, out ClaimsPrincipal principal)
        {
            X509Certificate2 clientCertificate = null;
            principal = null;

            if (TryGetClientCertificateFromRequest(request, out clientCertificate))
            {
                string userName;
                if (UserRepository.ValidateUser(clientCertificate, out userName))
                {
                    principal = CreatePrincipal(userName, AuthenticationMethods.X509);
                    return true;
                }
            }

            return false;
        }

        public bool TryGetClientCertificateFromRequest(HttpRequestBase request, out X509Certificate2 clientCertificate)
        {
            clientCertificate = null;

            if (request.ClientCertificate.IsPresent && request.ClientCertificate.IsValid)
            {
                clientCertificate = new X509Certificate2(request.ClientCertificate.Certificate);
                return true;
            }

            return false;
        }

        public bool TryGetClientCertificateFromRequest(HttpRequestMessage request, out X509Certificate2 clientCertificate)
        {
            clientCertificate = request.GetClientCertificate();

            if (clientCertificate != null)
            {
                return true;
            }

            return false;
        }
        #endregion

        #region Basic Authentication
        public bool TryGetBasicAuthenticationPrincipalFromRequest(HttpRequestBase request, out ClaimsPrincipal principal)
        {
            principal = null;
            HttpListenerBasicIdentity identity = null;

            if (TryGetBasicAuthenticationCredentialsFromRequest(request, out identity))
            {
                if (UserRepository.ValidateUser(identity.Name, identity.Password))
                {
                    principal = CreatePrincipal(identity.Name, AuthenticationMethods.Password);
                    return true;
                }
            }

            return false;
        }

        public bool TryGetBasicAuthenticationPrincipalFromRequest(HttpRequestMessage request, out ClaimsPrincipal principal)
        {
            principal = null;
            HttpListenerBasicIdentity identity = null;

            if (TryGetBasicAuthenticationCredentialsFromRequest(request, out identity))
            {
                if (UserRepository.ValidateUser(identity.Name, identity.Password))
                {
                    principal = CreatePrincipal(identity.Name, AuthenticationMethods.Password);
                    return true;
                }
            }

            return false;
        }

        public bool TryGetBasicAuthenticationCredentialsFromRequest(HttpRequestBase request, out HttpListenerBasicIdentity identity)
        {
            identity = null;

            string header = request.Headers["Authorization"] ?? request.Headers["X-Authorization"];
            if (header != null && header.StartsWith("Basic"))
            {
                string encodedUserPass = header.Substring(6).Trim();

                Encoding encoding = Encoding.GetEncoding("iso-8859-1");
                string userPass = encoding.GetString(Convert.FromBase64String(encodedUserPass));
                int separator = userPass.IndexOf(':');

                string[] credentials = new string[2];
                credentials[0] = userPass.Substring(0, separator);
                credentials[1] = userPass.Substring(separator + 1);

                identity = new HttpListenerBasicIdentity(credentials[0], credentials[1]);
                return true;
            }

            return false;
        }

        public bool TryGetBasicAuthenticationCredentialsFromRequest(HttpRequestMessage request, out HttpListenerBasicIdentity identity)
        {
            identity = null;

            var header = request.Headers.Authorization;
            if (header != null && header.Scheme.Equals("Basic"))
            {
                string encodedUserPass = header.Parameter;

                Encoding encoding = Encoding.GetEncoding("iso-8859-1");
                string userPass = encoding.GetString(Convert.FromBase64String(encodedUserPass));
                int separator = userPass.IndexOf(':');

                string[] credentials = new string[2];
                credentials[0] = userPass.Substring(0, separator);
                credentials[1] = userPass.Substring(separator + 1);

                identity = new HttpListenerBasicIdentity(credentials[0], credentials[1]);
                return true;
            }

            return false;
        }
        #endregion

        public ClaimsPrincipal CreatePrincipal(string username, string authenticationMethod, IEnumerable<Claim> additionalClaims = null)
        {
            var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, username),
                        new Claim(ClaimTypes.Name, username),
                        new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod),
                        AuthenticationInstantClaim.Now,
                    };

            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Constants.AuthenticationType));

            // add additional claims if present
            if (additionalClaims != null)
            {
                additionalClaims.ToList().ForEach(c => principal.Identities.First().AddClaim(c));
            }

            return FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager.Authenticate(string.Empty, principal);
        }

        public void SetSessionToken(string userName, string authenticationMethod, bool isPersistent, int ttl, IEnumerable<Claim> additionalClaims = null)
        {
            var principal = CreatePrincipal(userName, authenticationMethod, additionalClaims);

            var sessionToken = new SessionSecurityToken(principal, TimeSpan.FromHours(ttl))
            {
                IsPersistent = isPersistent
            };

            FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionToken);
        }

        public RelyingParty GetRelyingPartyDetails(string realm)
        {
            RelyingParty rp = null;

            if (RelyingPartyRepository.TryGet(realm, out rp))
            {
                return rp;
            }

            return null;
        }

        public RelyingParty GetRelyingPartyDetailsFromReturnUrl(string returnUrl)
        {
            if (string.IsNullOrWhiteSpace(returnUrl))
            {
                return null;
            }

            var url = HttpUtility.UrlDecode(returnUrl);
            Uri uri;

            if (Uri.TryCreate("http://foo.com" + url, UriKind.Absolute, out uri))
            {
                WSFederationMessage message;

                if (WSFederationMessage.TryCreateFromUri(uri, out message))
                {
                    var signin = message as SignInRequestMessage;
                    if (signin != null)
                    {
                        return GetRelyingPartyDetails(signin.Realm);
                    }
                }
            }

            return null;
        }
    }
}