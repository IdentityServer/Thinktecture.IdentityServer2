/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;
using Thinktecture.IdentityModel.Clients;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityModel.Tokens;
using Thinktecture.IdentityModel.Tokens.Http;

namespace Thinktecture.IdentityServer.Tests
{
    [TestClass]
    public class OAuth2Tests
    {
        string baseAddress = Constants.OAuth2.LocalBaseAddress;
        //string baseAddress = Constants.OAuth2.CloudBaseAddress;

        string scopeSymmetric = Constants.Realms.TestRPSymmetric;
        string scopeAsymmetric = Constants.Realms.TestRPAsymmetric;

        [TestMethod]
        public void ValidUserNameCredentialValidClientCredentialSymmetric()
        {
            var client = new OAuth2Client(
                new Uri(baseAddress),
                Constants.Credentials.ValidClientId,
                Constants.Credentials.ValidClientSecret);

            var response = client.RequestAccessTokenUserName(
                Constants.Credentials.ValidUserName,
                Constants.Credentials.ValidPassword,
                scopeSymmetric);

            Assert.IsTrue(response != null, "response is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.AccessToken), "access token is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.TokenType), "token type is null");
            Assert.IsTrue(response.ExpiresIn > 0, "expiresIn is 0");

            Trace.WriteLine(response.AccessToken);
        }

        [TestMethod]
        public void ValidUserNameCredentialValidClientCredentialAsymmetric()
        {
            var client = new OAuth2Client(
                new Uri(baseAddress),
                Constants.Credentials.ValidClientId,
                Constants.Credentials.ValidClientSecret);

            var response = client.RequestAccessTokenUserName(
                Constants.Credentials.ValidUserName,
                Constants.Credentials.ValidPassword,
                scopeAsymmetric);

            Assert.IsTrue(response != null, "response is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.AccessToken), "access token is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.TokenType), "token type is null");
            Assert.IsTrue(response.ExpiresIn > 0, "expiresIn is 0");

            Trace.WriteLine(response.AccessToken);
        }

        [TestMethod]
        public void ValidUserNameCredentialValidClientCredentialUseRefreshToken()
        {
            var client = new OAuth2Client(
                new Uri(baseAddress),
                Constants.Credentials.ValidClientId,
                Constants.Credentials.ValidClientSecret);

            var response = client.RequestAccessTokenUserName(
                Constants.Credentials.ValidUserName,
                Constants.Credentials.ValidPassword,
                scopeSymmetric);

            Assert.IsTrue(response != null, "response is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.AccessToken), "access token is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.TokenType), "token type is null");
            Assert.IsTrue(response.ExpiresIn > 0, "expiresIn is 0");

            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.RefreshToken));

            var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { OAuth2Constants.GrantType, "refresh_token" },
                    { "refresh_token", response.RefreshToken },
                    { OAuth2Constants.Scope, scopeSymmetric }
                });

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(Constants.Credentials.ValidClientId, Constants.Credentials.ValidClientSecret);

            var result = httpClient.PostAsync(new Uri(baseAddress), form).Result;
            Assert.AreEqual<HttpStatusCode>(HttpStatusCode.OK, result.StatusCode);          
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public void ValidUserNameCredentialMissingClientCredential()
        {
            var client = new OAuth2Client(new Uri(baseAddress));

            var response = client.RequestAccessTokenUserName(
                Constants.Credentials.ValidUserName,
                Constants.Credentials.ValidPassword,
                scopeSymmetric);
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException))]
        public void ValidUserNameCredentialInvalidClientCredential()
        {
            var client = new OAuth2Client(new Uri(baseAddress), "invalid", "invalid");

            var response = client.RequestAccessTokenUserName(
                Constants.Credentials.ValidUserName,
                Constants.Credentials.ValidPassword,
                scopeSymmetric);

            Assert.IsTrue(response != null, "response is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.AccessToken), "access token is null");
            Assert.IsTrue(!string.IsNullOrWhiteSpace(response.TokenType), "token type is null");
            Assert.IsTrue(response.ExpiresIn > 0, "expiresIn is 0");

            Trace.WriteLine(response.AccessToken);
        }

        // todo
        //[TestMethod]
        //public void ValidUserNameCredentialWithTokenValidation()
        //{
        //    var client = new OAuth2Client(
        //        new Uri(baseAddress),
        //        Constants.Credentials.ValidClientId,
        //        Constants.Credentials.ValidClientSecret);

        //    var response = client.RequestAccessTokenUserName(
        //        Constants.Credentials.ValidUserName,
        //        Constants.Credentials.ValidPassword,
        //        scopeSymmetric);

        //    Assert.IsTrue(response != null, "response is null");
        //    Assert.IsTrue(!string.IsNullOrWhiteSpace(response.AccessToken), "access token is null");
        //    Assert.IsTrue(!string.IsNullOrWhiteSpace(response.TokenType), "token type is null");
        //    Assert.IsTrue(response.ExpiresIn > 0, "expiresIn is 0");

        //    Trace.WriteLine(response.AccessToken);

        //    var config = new SecurityTokenHandlerConfiguration();
        //    var registry = new WebTokenIssuerNameRegistry();
        //    registry.AddTrustedIssuer("http://identityserver.v2.thinktecture.com/trust/changethis", "http://identityserver45.thinktecture.com/trust/initial");
        //    config.IssuerNameRegistry = registry;

        //    var issuerResolver = new WebTokenIssuerTokenResolver();
        //    issuerResolver.AddSigningKey("http://identityserver.v2.thinktecture.com/trust/changethis", "fWUU28oBOIcaQuwUKiL01KztD/CsZX83C3I0M1MOYN4=");
        //    config.IssuerTokenResolver = issuerResolver;

        //    config.AudienceRestriction.AllowedAudienceUris.Add(new Uri(scopeSymmetric));

        //    var handler = new JsonWebTokenHandler();
        //    handler.Configuration = config;

        //    var jwt = handler.ReadToken(response.AccessToken);

        //    var id = handler.ValidateToken(jwt);
        //}

        [TestMethod]
        public void InvalidUserNameCredential()
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { OAuth2Constants.GrantType, OAuth2Constants.Password },
                    { OAuth2Constants.UserName, Constants.Credentials.ValidUserName },
                    { OAuth2Constants.Password, "invalid" },
                    { OAuth2Constants.Scope, scopeSymmetric }
                });

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(Constants.Credentials.ValidClientId, Constants.Credentials.ValidClientSecret);

            var result = client.PostAsync(new Uri(baseAddress), form).Result;

            Assert.AreEqual<HttpStatusCode>(HttpStatusCode.BadRequest, result.StatusCode);            
        }

        [TestMethod]
        public void UnauthorizedUser()
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { OAuth2Constants.GrantType, OAuth2Constants.Password },
                    { OAuth2Constants.UserName, Constants.Credentials.UnauthorizedUserName },
                    { OAuth2Constants.Password, Constants.Credentials.ValidPassword },
                    { OAuth2Constants.Scope, scopeSymmetric }
                });

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(Constants.Credentials.ValidClientId, Constants.Credentials.ValidClientSecret);
            var result = client.PostAsync(new Uri(baseAddress), form).Result;

            Assert.AreEqual<HttpStatusCode>(HttpStatusCode.BadRequest, result.StatusCode);
        }

        [TestMethod]
        public void NoRealm()
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { OAuth2Constants.GrantType, OAuth2Constants.Password },
                    { OAuth2Constants.UserName, Constants.Credentials.ValidUserName },
                    { OAuth2Constants.Password, Constants.Credentials.ValidUserName }
                });

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(Constants.Credentials.ValidClientId, Constants.Credentials.ValidClientSecret);
            var result = client.PostAsync(new Uri(baseAddress), form).Result;

            Assert.AreEqual<HttpStatusCode>(HttpStatusCode.BadRequest, result.StatusCode);
        }

        [TestMethod]
        public void MalformedRealm()
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { OAuth2Constants.GrantType, OAuth2Constants.Password },
                    { OAuth2Constants.UserName, Constants.Credentials.ValidUserName },
                    { OAuth2Constants.Password, Constants.Credentials.ValidUserName },
                    { OAuth2Constants.Scope, "invalid" }
                });

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(Constants.Credentials.ValidClientId, Constants.Credentials.ValidClientSecret);
            var result = client.PostAsync(new Uri(baseAddress), form).Result;

            Assert.AreEqual<HttpStatusCode>(HttpStatusCode.BadRequest, result.StatusCode);
        }

        [TestMethod]
        public void InvalidGrantType()
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { OAuth2Constants.GrantType, "invalid" },
                    { OAuth2Constants.UserName, Constants.Credentials.ValidUserName },
                    { OAuth2Constants.Password, Constants.Credentials.ValidUserName },
                    { OAuth2Constants.Scope, scopeSymmetric }
                });

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(Constants.Credentials.ValidClientId, Constants.Credentials.ValidClientSecret);
            var result = client.PostAsync(new Uri(baseAddress), form).Result;

            Assert.AreEqual<HttpStatusCode>(HttpStatusCode.BadRequest, result.StatusCode);
        }

        [TestMethod]
        public void NoUserCredentials()
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { OAuth2Constants.GrantType, OAuth2Constants.Password },
                    { OAuth2Constants.Scope, scopeSymmetric }
                });

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(Constants.Credentials.ValidClientId, Constants.Credentials.ValidClientSecret);

            var result = client.PostAsync(new Uri(baseAddress), form).Result;

            Assert.AreEqual<HttpStatusCode>(HttpStatusCode.BadRequest, result.StatusCode);
        }
    }
}