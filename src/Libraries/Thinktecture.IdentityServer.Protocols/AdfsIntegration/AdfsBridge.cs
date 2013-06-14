using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Xml;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityModel.Extensions;
using Thinktecture.IdentityModel.WSTrust;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.AdfsIntegration
{
    internal class AdfsBridge
    {
        IConfigurationRepository _configuration;
        SecurityTokenHandlerCollection _handler;
            
        public AdfsBridge(IConfigurationRepository configuration)
        {
            _configuration = configuration;
            _handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
        }

        public GenericXmlSecurityToken AuthenticateUserName(string userName, string password, string appliesTo)
        {
            var credentials = new ClientCredentials();
            credentials.UserName.UserName = userName;
            credentials.UserName.Password = password;

            return WSTrustClient.Issue(
                new EndpointAddress(_configuration.AdfsIntegration.UserNameAuthenticationEndpoint),
                new EndpointAddress(appliesTo),
                new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential),
                credentials) as GenericXmlSecurityToken;
        }

        public GenericXmlSecurityToken Authenticate(ClaimsIdentity identity, string appliesTo)
        {
            var encryptingCert = _configuration.AdfsIntegration.EncryptionCertificate;

            // create new token
            var proof = CreateProofDescriptor(encryptingCert);
            var outputToken = CreateOutputSamlToken(identity, proof, encryptingCert);

            // turn token into a generic xml security token
            var outputTokenString = outputToken.ToTokenXmlString();

            // create attached and unattached references
            var handler = new SamlSecurityTokenHandler();
            var ar = handler.CreateSecurityTokenReference(outputToken, true);
            var uar = handler.CreateSecurityTokenReference(outputToken, false);

            var xmlToken = new GenericXmlSecurityToken(
                GetElement(outputTokenString),
                new BinarySecretSecurityToken(proof.GetKeyBytes()),
                DateTime.UtcNow,
                DateTime.UtcNow.AddHours(1),
                ar,
                uar,
                new ReadOnlyCollection<IAuthorizationPolicy>(new List<IAuthorizationPolicy>()));

            // send to ADFS federation endpoint
            return RequestFederationToken(xmlToken, appliesTo) as GenericXmlSecurityToken;
        }

        public GenericXmlSecurityToken AuthenticateSaml(string incomingToken, string appliesTo)
        {
            // turn string saml token into SecurityToken
            var samlToken = _handler.ReadToken(new XmlTextReader(new StringReader(incomingToken)));

            // validate saml token
            var identity = ValidateSamlToken(samlToken);

            return Authenticate(identity, appliesTo);
        }

        public GenericXmlSecurityToken AuthenticateJwt(string incomingToken, string appliesTo)
        {
            // validate jwt token
            var identity = ValidateJwtToken(incomingToken);

            return Authenticate(identity, appliesTo);
        }

        private XmlElement GetElement(string xml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc.DocumentElement;
        }

        private SecurityToken RequestFederationToken(GenericXmlSecurityToken xmlToken, string appliesTo)
        {
            var adfsEndpoint = this._configuration.AdfsIntegration.FederationEndpoint;

            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointReference(appliesTo),
                KeyType = KeyTypes.Bearer
            };

            var binding = new IssuedTokenWSTrustBinding();
            binding.SecurityMode = SecurityMode.TransportWithMessageCredential;

            var factory = new WSTrustChannelFactory(
                binding,
                new EndpointAddress(adfsEndpoint));
            factory.TrustVersion = TrustVersion.WSTrust13;
            factory.Credentials.SupportInteractive = false;

            var channel = factory.CreateChannelWithIssuedToken(xmlToken);
            return channel.Issue(rst);
        }

        private SecurityToken CreateOutputSamlToken(ClaimsIdentity identity, ProofDescriptor proof, X509Certificate2 encryptingCertificate)
        {
            string adfsIssuerUri = this._configuration.AdfsIntegration.IssuerUri;

            var encryptingCredentials = new EncryptedKeyEncryptingCredentials(
                new X509EncryptingCredentials(encryptingCertificate),
                256,
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc");

            var descriptor = new SecurityTokenDescriptor
            {
                AppliesToAddress = adfsIssuerUri,
                TokenIssuerName = _configuration.Global.IssuerUri,

                SigningCredentials = new X509SigningCredentials(_configuration.Keys.SigningCertificate), // signing creds of IdSrv
                EncryptingCredentials = encryptingCredentials,

                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddHours(1)),
                Proof = proof,
                Subject = identity,
                TokenType = TokenTypes.Saml2TokenProfile11
            };

            return _handler.CreateToken(descriptor) as Saml2SecurityToken;
        }

        private static SymmetricProofDescriptor CreateProofDescriptor(X509Certificate2 encryptingCertificate)
        {
            return new SymmetricProofDescriptor(
                256, 
                new X509EncryptingCredentials(encryptingCertificate));
        }

        public TokenResponse ConvertSamlToJwt(SecurityToken securityToken, string scope)
        {
            var subject = ValidateSamlToken(securityToken);

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = subject,
                AppliesToAddress = scope,
                SigningCredentials = new X509SigningCredentials(_configuration.Keys.SigningCertificate),
                TokenIssuerName = _configuration.Global.IssuerUri,
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(_configuration.AdfsIntegration.AuthenticationTokenLifetime))
            };

            var jwtHandler = new JwtSecurityTokenHandler();
            var jwt = jwtHandler.CreateToken(descriptor);

            return new TokenResponse
            {
                AccessToken = jwtHandler.WriteToken(jwt),
                ExpiresIn = _configuration.AdfsIntegration.AuthenticationTokenLifetime
            };
        }

        public ClaimsIdentity ValidateSamlToken(SecurityToken securityToken)
        {
            var configuration = new SecurityTokenHandlerConfiguration();
            configuration.AudienceRestriction.AudienceMode = AudienceUriMode.Never;
            configuration.CertificateValidationMode = X509CertificateValidationMode.None;
            configuration.RevocationMode = X509RevocationMode.NoCheck;
            configuration.CertificateValidator = X509CertificateValidator.None;

            var registry = new ConfigurationBasedIssuerNameRegistry();
            registry.AddTrustedIssuer(_configuration.AdfsIntegration.IssuerThumbprint, "ADFS");
            configuration.IssuerNameRegistry = registry;

            var handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection(configuration);
            var identity = handler.ValidateToken(securityToken).First();
            return identity;
        }

        public ClaimsIdentity ValidateJwtToken(string jwt)
        {
            var handler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters()
            {
                AudienceUriMode = AudienceUriMode.Never,
                SigningToken = new X509SecurityToken(_configuration.Keys.SigningCertificate),
                ValidIssuer = _configuration.Global.IssuerUri,
            };

            var principal = handler.ValidateToken(jwt, validationParameters);
            return principal.Identities.First();
        }
    }
}
