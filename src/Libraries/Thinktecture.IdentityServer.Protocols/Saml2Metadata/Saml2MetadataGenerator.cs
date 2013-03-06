using System;
using System.ComponentModel.Composition;
using System.IO;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.Saml2.Constants;
using Thinktecture.IdentityServer.Repositories;
using EntityDescriptor = Microsoft.IdentityModel.Protocols.WSFederation.Metadata.EntityDescriptor;
using IndexedProtocolEndpoint = Microsoft.IdentityModel.Protocols.WSFederation.Metadata.IndexedProtocolEndpoint;
using MetadataSerializer = Microsoft.IdentityModel.Protocols.WSFederation.Metadata.MetadataSerializer;
using ProtocolEndpoint = Microsoft.IdentityModel.Protocols.WSFederation.Metadata.ProtocolEndpoint;
using ServiceProviderSingleSignOnDescriptor = Microsoft.IdentityModel.Protocols.WSFederation.Metadata.ServiceProviderSingleSignOnDescriptor;
using X509SigningCredentials = Microsoft.IdentityModel.SecurityTokenService.X509SigningCredentials;

namespace Thinktecture.IdentityServer.Protocols.Saml2Metadata
{
    /// <summary>
    /// Handler for dynamic generation of the WS-Federation metadata document
    /// </summary>
    public class Saml2MetadataGenerator
    {
        readonly Endpoints _endpoints;

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IClaimsRepository ClaimsRepository { get; set; }

        static string _entityId;
        static X509Certificate2 _signingCertificate;

        public Saml2MetadataGenerator(Endpoints endpoints)
        {
            _endpoints = endpoints;
            Container.Current.SatisfyImportsOnce(this);
        }
        public string GenerateMetadataDocument()
        {
            var metadata = CreateMetadata();
            var serializer = new MetadataSerializer();

            var prettyPrintSettings = new XmlWriterSettings
                                          {Indent = true, OmitXmlDeclaration = true, NewLineOnAttributes = true};


            var stream = new MemoryStream();

            using (var writer = XmlWriter.Create(stream, prettyPrintSettings))
            {
                serializer.WriteMetadata(writer, metadata);
                writer.Flush();
            }

            var xDocument = new XmlDocument();
            stream.Position = 0;
            xDocument.Load(stream);
            return xDocument.OuterXml;
        }
        /// <summary>
        /// Create Saml2 based Metadata
        /// </summary>
        /// <returns></returns>
        public EntityDescriptor CreateMetadata()
        {
            _entityId = ConfigurationRepository.Global.IssuerUri;

            _signingCertificate = ConfigurationRepository.Keys.SigningCertificate;

            var descriptor = new EntityDescriptor(new Microsoft.IdentityModel.Protocols.WSFederation.Metadata.EntityId(_entityId));

            var role = new ServiceProviderSingleSignOnDescriptor() { WantAssertionsSigned = true, AuthenticationRequestsSigned = true };

            if (_signingCertificate != null)
            {
                Microsoft.IdentityModel.Protocols.WSFederation.Metadata.KeyDescriptor keyDescriptor = CreateKeyDescriptor(_signingCertificate);
                keyDescriptor.Use = Microsoft.IdentityModel.Protocols.WSFederation.Metadata.KeyType.Signing;
                role.Keys.Add(keyDescriptor);
            }

            role.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));

            role.AssertionConsumerService.Add(0, new IndexedProtocolEndpoint(0, ProtocolBindings.HttpPost, new Uri(_endpoints.Saml2ASTPost.AbsoluteUri)) { IsDefault = true });
            role.SingleLogoutServices.Add(new ProtocolEndpoint(ProtocolBindings.HttpPost, new Uri(_endpoints.Saml2SLOPOST.AbsoluteUri)) { ResponseLocation = new Uri(_endpoints.Saml2SLOPostResponse.AbsoluteUri) });

            //
            // Artifact binding and single logout is only supported if there is a signing cerificate.
            //
            if (_signingCertificate != null)
            {
                role.AssertionConsumerService.Add(1, new IndexedProtocolEndpoint(1, ProtocolBindings.HttpArtifact, new Uri(_endpoints.Saml2ASTArtifact.AbsoluteUri)));
                role.AssertionConsumerService.Add(2, new IndexedProtocolEndpoint(2, ProtocolBindings.HttpRedirect, new Uri(_endpoints.Saml2ASTRedirect.AbsoluteUri)));
                role.SingleLogoutServices.Add(new ProtocolEndpoint(ProtocolBindings.HttpRedirect, new Uri(_endpoints.Saml2SLORedirect.AbsoluteUri)) { ResponseLocation = new Uri(_endpoints.Saml2SLORedirectResponse.AbsoluteUri) });
            }

            descriptor.RoleDescriptors.Add(role);
            return descriptor;
        }

        static Microsoft.IdentityModel.Protocols.WSFederation.Metadata.KeyDescriptor CreateKeyDescriptor(X509Certificate2 certificate)
        {
            var keyDescriptor = new Microsoft.IdentityModel.Protocols.WSFederation.Metadata.KeyDescriptor
                                    {
                                        KeyInfo = new SecurityKeyIdentifier(new X509RawDataKeyIdentifierClause(certificate))
                                    };
            return keyDescriptor;
        }

    }
}