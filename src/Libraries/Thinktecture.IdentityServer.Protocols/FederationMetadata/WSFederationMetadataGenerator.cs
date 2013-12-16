/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.Composition;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Xml;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Models.Configuration;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.FederationMetadata
{
    /// <summary>
    /// Handler for dynamic generation of the WS-Federation metadata document
    /// </summary>
    public class WSFederationMetadataGenerator
    {
        Endpoints _endpoints;

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IClaimsRepository ClaimsRepository { get; set; }

        public WSFederationMetadataGenerator(Endpoints endpoints)
        {
            _endpoints = endpoints;
            Container.Current.SatisfyImportsOnce(this);
        }

        public string Generate()
        {
            var tokenServiceDescriptor = GetTokenServiceDescriptor();
            var id = new EntityId(ConfigurationRepository.Global.IssuerUri);
            var entity = new EntityDescriptor(id);
            entity.SigningCredentials = new X509SigningCredentials(ConfigurationRepository.Keys.SigningCertificate);
            entity.RoleDescriptors.Add(tokenServiceDescriptor);

            var ser = new MetadataSerializer();
            var sb = new StringBuilder(512);

            ser.WriteMetadata(XmlWriter.Create(new StringWriter(sb), new XmlWriterSettings { OmitXmlDeclaration = true }), entity);
            return sb.ToString();
        }

        private SecurityTokenServiceDescriptor GetTokenServiceDescriptor()
        {
            var tokenService = new SecurityTokenServiceDescriptor();
            tokenService.ServiceDescription = ConfigurationRepository.Global.SiteName;
            tokenService.Keys.Add(GetSigningKeyDescriptor());

            tokenService.PassiveRequestorEndpoints.Add(new EndpointReference(GetWsFedUrlForEnableFederation().AbsoluteUri));

            tokenService.TokenTypesOffered.Add(new Uri(TokenTypes.OasisWssSaml11TokenProfile11));
            tokenService.TokenTypesOffered.Add(new Uri(TokenTypes.OasisWssSaml2TokenProfile11));

            ClaimsRepository.GetSupportedClaimTypes().ToList().ForEach(claimType => tokenService.ClaimTypesOffered.Add(new DisplayClaim(claimType)));
            tokenService.ProtocolsSupported.Add(new Uri("http://docs.oasis-open.org/wsfed/federation/200706"));

            if (ConfigurationRepository.WSTrust.Enabled && ConfigurationRepository.WSTrust.EnableMessageSecurity)
            {
                var addressMessageUserName = new EndpointAddress(_endpoints.WSTrustMessageUserName, null, null, CreateMetadataReader(_endpoints.WSTrustMex), null);
                tokenService.SecurityTokenServiceEndpoints.Add(new EndpointReference(addressMessageUserName.Uri.AbsoluteUri));

                if (ConfigurationRepository.WSTrust.EnableClientCertificateAuthentication)
                {
                    var addressMessageCertificate = new EndpointAddress(_endpoints.WSTrustMessageCertificate, null, null, CreateMetadataReader(_endpoints.WSTrustMex), null);
                    tokenService.SecurityTokenServiceEndpoints.Add(new EndpointReference(addressMessageCertificate.Uri.AbsoluteUri));
                }
            }
            if (ConfigurationRepository.WSTrust.Enabled && ConfigurationRepository.WSTrust.EnableMixedModeSecurity)
            {
                var addressMixedUserName = new EndpointAddress(_endpoints.WSTrustMixedUserName, null, null, CreateMetadataReader(_endpoints.WSTrustMex), null);
                tokenService.SecurityTokenServiceEndpoints.Add(new EndpointReference(addressMixedUserName.Uri.AbsoluteUri));

                if (ConfigurationRepository.WSTrust.EnableClientCertificateAuthentication)
                {
                    var addressMixedCertificate = new EndpointAddress(_endpoints.WSTrustMixedCertificate, null, null, CreateMetadataReader(_endpoints.WSTrustMex), null);
                    tokenService.SecurityTokenServiceEndpoints.Add(new EndpointReference(addressMixedCertificate.Uri.AbsoluteUri));
                }
            }

            if (tokenService.SecurityTokenServiceEndpoints.Count == 0)
                tokenService.SecurityTokenServiceEndpoints.Add(new EndpointReference(_endpoints.WSFederation.AbsoluteUri));

            return tokenService;
        }

        private Uri GetWsFedUrlForEnableFederation()
        {
            // If Federation is enabled (this server is a gateway) then use the HRD enpoint instead of the standard WsFed endpoint.
            switch (ConfigurationRepository.FederationMetadata.PrimaryPassiveEndpoint)
            {
                case PassiveEndpoints.Hrd:
                    return _endpoints.WSFederationHRD;
                default:
                    return _endpoints.WSFederation;
            }
        }

        private KeyDescriptor GetSigningKeyDescriptor()
        {
            var certificate = ConfigurationRepository.Keys.SigningCertificate;

            var clause = new X509SecurityToken(certificate).CreateKeyIdentifierClause<X509RawDataKeyIdentifierClause>();
            var key = new KeyDescriptor(new SecurityKeyIdentifier(clause));
            key.Use = KeyType.Signing;

            return key;
        }

        private XmlDictionaryReader CreateMetadataReader(Uri mexAddress)
        {
            var metadataSet = new MetadataSet();
            var metadataReference = new MetadataReference(new EndpointAddress(mexAddress), AddressingVersion.WSAddressing10);
            var metadataSection = new MetadataSection(MetadataSection.MetadataExchangeDialect, null, metadataReference);
            metadataSet.MetadataSections.Add(metadataSection);

            var sb = new StringBuilder();
            var w = new StringWriter(sb, CultureInfo.InvariantCulture);
            var writer = XmlWriter.Create(w);

            metadataSet.WriteTo(writer);
            writer.Flush();
            w.Flush();

            var input = new StringReader(sb.ToString());
            var reader = new XmlTextReader(input);
            return XmlDictionaryReader.CreateDictionaryReader(reader);
        }
    }
}