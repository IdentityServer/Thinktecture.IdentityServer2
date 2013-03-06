/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.Composition;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.TokenService
{
    /// <summary>
    /// This class contains the token issuance logic
    /// </summary>
    public class SamlTokenService : SecurityTokenService
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

        public SamlTokenService(SecurityTokenServiceConfiguration configuration)
            : base(configuration)
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public SamlTokenService(SecurityTokenServiceConfiguration configuration, IConfigurationRepository configurationRepository, IUserRepository userRepository, IClaimsRepository claimsRepository, IIdentityProviderRepository identityProviderRepository, IClaimsTransformationRulesRepository claimsTransformationRulesRepository)
            : base(configuration)
        {
            UserRepository = userRepository;
            ClaimsRepository = claimsRepository;
            IdentityProviderRepository = identityProviderRepository;
            ClaimsTransformationRulesRepository = claimsTransformationRulesRepository;
            ConfigurationRepository = configurationRepository;
        }

        
        /// <summary>
        /// Need to implement Certificate with Signing Credentials
        /// </summary>
        protected override Scope GetScope(IClaimsPrincipal principal, RequestSecurityToken request)
        {

            var scope = new Scope(request.AppliesTo.ToString())
                              {
                                  EncryptingCredentials = GetCredentialsForAppliesTo(request.AppliesTo),
                                  SymmetricKeyEncryptionRequired = false,
                                  // SigningCredentials = new X509SigningCredentials(GetCertificate(StoreName.My, StoreLocation.LocalMachine, "CN=IdentityProvider")),
                                  ReplyToAddress = request.AppliesTo.ToString()
                              };
            return scope;
        }

        private X509EncryptingCredentials GetCredentialsForAppliesTo(EndpointAddress appliesTo)
        {
            if (appliesTo == null || appliesTo.Uri == null || string.IsNullOrEmpty(appliesTo.Uri.AbsolutePath))
            {
                throw new InvalidRequestException("AppliesTo must be supplied in the RST.");
            }

            X509EncryptingCredentials creds;
            if (!string.IsNullOrWhiteSpace(appliesTo.Uri.AbsoluteUri))
            {
                creds = new X509EncryptingCredentials(GetCertificate(StoreName.My, StoreLocation.LocalMachine));
            }
            else
                throw new InvalidRequestException(String.Format("Invalid relying party address: {0}", appliesTo.Uri.AbsoluteUri));

            return creds;
        }

        /// <summary>
        ///   Need to implement if more than saml2 type provider is available. 
        /// Get Identity provider based on Incoming Request.
        /// </summary>
        public X509Certificate2 GetCertificate(StoreName name, StoreLocation location)
        {
            IdentityProvider idp = null;
            var idps = IdentityProviderRepository.GetAll();
            foreach (var identityProvider in idps)
            {
                if (identityProvider.Type == IdentityProviderTypes.Saml2)
                {
                    idp = identityProvider;
                }
            }

            if (idp == null)
                return null;
            //IdentityProviderRepository.TryGet("OIOSAML", out idp);

            var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            try
            {
                var certificateCollection = store.Certificates.Find(X509FindType.FindByThumbprint, idp.IssuerThumbprint, true);

                if (certificateCollection[0] == null)
                {
                    throw new ApplicationException(string.Format("No certificate was found for subject Name"));
                }

                return certificateCollection[0];
            }

            finally
            {
                store.Close();
            }
        }


        /// <summary>
        /// This method returns the claims to be included in the issued token. 
        /// </summary>
        /// <param name="scope">The scope that was previously returned by GetScope method</param>
        /// <param name="principal">The caller's principal</param>
        /// <param name="request">The incoming RST</param>
        /// <returns>The claims to be included in the issued token.</returns>
        protected override IClaimsIdentity GetOutputClaimsIdentity(IClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            return (IClaimsIdentity)principal.Identity;
        }


        
        /// <summary>
        /// Need to implement to check the token life time
        /// </summary>
        /// <param name="requestLifetime"></param>
        /// <returns></returns>
        protected override Lifetime GetTokenLifetime(Lifetime requestLifetime)
        {
            var scope = Scope as SamlRequestDetailsScope;
            //var rp = scope.RequestDetails.RelyingPartyRegistration;

            //if (!scope.RequestDetails.IsKnownRealm || rp.TokenLifeTime == 0)
            //{
            //    return base.GetTokenLifetime(requestLifetime);
            //}

            //var lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(rp.TokenLifeTime));
            return null;
        }
    }
}