/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.TokenService
{
    /// <summary>
    /// This class contains the token issuance logic
    /// </summary>
    public class TokenService : SecurityTokenService
    {
        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IClaimsRepository ClaimsRepository { get; set; }

        [Import]
        public IIdentityProviderRepository IdentityProviderRepository { get; set; }

        [Import]
        public IClaimsTransformationRulesRepository ClaimsTransformationRulesRepository { get; set; }

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public TokenService(SecurityTokenServiceConfiguration configuration)
            : base(configuration)
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public TokenService(SecurityTokenServiceConfiguration configuration, IConfigurationRepository configurationRepository, IUserRepository userRepository, IClaimsRepository claimsRepository, IIdentityProviderRepository identityProviderRepository, IClaimsTransformationRulesRepository claimsTransformationRulesRepository)
            : base(configuration)
        {
            UserRepository = userRepository;
            ClaimsRepository = claimsRepository;
            IdentityProviderRepository = identityProviderRepository;
            ClaimsTransformationRulesRepository = claimsTransformationRulesRepository;
            ConfigurationRepository = configurationRepository;
        }

        /// <summary>
        /// Analyzes the token request
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="request">The request.</param>
        /// <returns>A PolicyScope that describes the relying party and policy options</returns>
        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken rst)
        {
            if (rst.AppliesTo == null)
            {
                Tracing.Error(string.Format("token request from {0} - but no realm specified.",
                    principal.Identity.Name));

                throw new InvalidRequestException();
            }

            Tracing.Information(string.Format("Starting token request from {0} for {1}",
                principal.Identity.Name,
                rst.AppliesTo.Uri.AbsoluteUri));

            var authenticationMethod = principal.Identities.First().FindFirst(ClaimTypes.AuthenticationMethod);
            if (authenticationMethod != null)
            {
                Tracing.Information("Authentication method: " + authenticationMethod.Value);
            }

            // analyze request
            var request = new Request(ConfigurationRepository);
            var details = request.Analyze(rst, principal);

            // validate against policy
            request.Validate(details);

            // create scope
            var scope = new RequestDetailsScope(
                details, 
                SecurityTokenServiceConfiguration.SigningCredentials, 
                ConfigurationRepository.Global.RequireEncryption);

            // set token type
            if (!string.IsNullOrWhiteSpace(details.TokenType))
            {
                rst.TokenType = details.TokenType;
            }


            return scope;
        }
        
        protected override Lifetime GetTokenLifetime(Lifetime requestLifetime)
        {
            var scope = Scope as RequestDetailsScope;
            var rp = scope.RequestDetails.RelyingPartyRegistration;

            if (!scope.RequestDetails.IsKnownRealm || rp.TokenLifeTime == 0)
            {
                return base.GetTokenLifetime(requestLifetime);
            }

            var lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(rp.TokenLifeTime));
            return lifetime;
        }

        /// <summary>
        /// Produces the output identity that gets transformed into a token
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="request">The request.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An IClaimsIdentity describing the subject</returns>
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            var requestDetails = (scope as RequestDetailsScope).RequestDetails;

            // externally authenticated user
            if (principal.HasClaim(c => c.Type == Constants.Claims.IdentityProvider && c.Issuer == Constants.InternalIssuer))
            {
                Tracing.Information("Issuing a token for an external user.");
                return GetExternalOutputClaims(principal, requestDetails);
            }

            var userClaims = GetOutputClaims(principal, requestDetails, ClaimsRepository);
            var outputIdentity = new ClaimsIdentity(userClaims, "IdSrv");

            if (requestDetails.IsActAsRequest)
            {
                Tracing.Information("Issuing act as token");
                return GetActAsClaimsIdentity(outputIdentity, requestDetails);
            }
            else
            {
                Tracing.Information("Issuing identity token");
                return outputIdentity;
            }
        }

        public static List<Claim> GetOutputClaims(ClaimsPrincipal principal, RequestDetails requestDetails, IClaimsRepository claimsRepository)
        {
            return claimsRepository.GetClaims(SanitizeInternalClaims(principal), requestDetails).ToList();
        }

        protected virtual ClaimsIdentity GetExternalOutputClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            var idpClaim = principal.FindFirst(c => c.Type == Constants.Claims.IdentityProvider && c.Issuer == Constants.InternalIssuer);

            if (idpClaim == null)
            {
                throw new InvalidOperationException("No identity provider claim found.");
            }

            IdentityProvider idp = null;
            if (IdentityProviderRepository.TryGet(idpClaim.Value, out idp))
            {
                var transformedClaims = ClaimsTransformationRulesRepository.ProcessClaims(SanitizeInternalClaims(principal), idp, requestDetails);
                var id = new ClaimsIdentity(transformedClaims, "External");

                id.AddClaim(new Claim(Constants.Claims.IdentityProvider, idp.Name));
                return id;
            }

            throw new InvalidRequestException("Invalid identity provider.");
        }

        protected virtual ClaimsIdentity GetActAsClaimsIdentity(ClaimsIdentity clientIdentity, RequestDetails requestDetails)
        {
            //var actAsSubject = requestDetails.Request.ActAs..GetSubject()[0];
            var actAsIdentity = requestDetails.Request.ActAs.GetIdentities().First();

            // find the last actor in the actAs identity
            ClaimsIdentity lastActor = actAsIdentity;
            while (lastActor.Actor != null)
            {
                lastActor = lastActor.Actor;
            }

            // set the caller's identity as the last actor in the delegation chain
            lastActor.Actor = clientIdentity;

            Tracing.Information("ActAs client identity: " + actAsIdentity.Name);
            Tracing.Information("ActAs actor identity : " + actAsIdentity.Actor.Name);

            // return the actAsIdentity instead of the caller's identity in this case
            return actAsIdentity;
        }

        protected static ClaimsPrincipal SanitizeInternalClaims(ClaimsPrincipal incomingPrincipal)
        {
            var userClaims = from c in incomingPrincipal.Claims
                             where !c.Issuer.Equals(Constants.InternalIssuer, StringComparison.Ordinal)
                             select c;

            var id = new ClaimsIdentity(userClaims, Constants.AuthenticationType);
            return new ClaimsPrincipal(id);
        }

        #region FederationMessageTracing
        protected override RequestSecurityTokenResponse GetResponse(RequestSecurityToken request, SecurityTokenDescriptor tokenDescriptor)
        {
            var response = base.GetResponse(request, tokenDescriptor);

            if (ConfigurationRepository.Diagnostics.EnableFederationMessageTracing)
            {
                Tracing.Information(SerializeRequest(request));
                Tracing.Information(SerializeResponse(response));
                Tracing.Information(SerializeToken(tokenDescriptor));
            }

            return response;
        }

        private string SerializeRequest(RequestSecurityToken request)
        {
            var serializer = new WSTrust13RequestSerializer();
            var context = new WSTrustSerializationContext();
            var sb = new StringBuilder(128);

            using (var writer = XmlWriter.Create(new StringWriter(sb)))
            {
                serializer.WriteXml(request, writer, context);
                return sb.ToString();
            }
        }

        private string SerializeResponse(RequestSecurityTokenResponse response)
        {
            var serializer = new WSTrust13ResponseSerializer();
            var context = new WSTrustSerializationContext(FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlerCollectionManager);
            var sb = new StringBuilder(128);

            using (var writer = XmlWriter.Create(new StringWriter(sb)))
            {
                serializer.WriteXml(response, writer, context);
                return sb.ToString();
            }
        }

        private string SerializeToken(SecurityTokenDescriptor tokenDescriptor)
        {
            // see if token is encrypted
            var encryptedToken = tokenDescriptor.Token as EncryptedSecurityToken;
            SecurityToken token;

            if (encryptedToken != null)
            {
                // use inner token
                token = encryptedToken.Token;
            }
            else
            {
                // if not, use the token directly
                token = tokenDescriptor.Token;
            }

            var sb = new StringBuilder(128);
            FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.WriteToken(XmlWriter.Create(new StringWriter(sb)), token);

            return sb.ToString();
        }
        #endregion
    }
}