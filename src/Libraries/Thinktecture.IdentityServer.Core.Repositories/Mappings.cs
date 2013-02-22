/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityServer.Models;
using Entities = Thinktecture.IdentityServer.Repositories.Sql;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    internal static class Mappings
    {
        #region GlobalConfiguration
        public static Models.Configuration.GlobalConfiguration ToDomainModel(this Entities.Configuration.GlobalConfiguration entity)
        {
            return new Models.Configuration.GlobalConfiguration
            {
                SiteName = entity.SiteName,
                IssuerUri = entity.IssuerUri,
                IssuerContactEmail = entity.IssuerContactEmail,
                DefaultHttpTokenType = entity.DefaultHttpTokenType,
                DefaultWSTokenType = entity.DefaultWSTokenType,
                DefaultTokenLifetime = entity.DefaultTokenLifetime,
                MaximumTokenLifetime = entity.MaximumTokenLifetime,
                EnableClientCertificateAuthentication = entity.EnableClientCertificateAuthentication,
                EnforceUsersGroupMembership = entity.EnforceUsersGroupMembership,
                HttpPort = entity.HttpPort,
                HttpsPort = entity.HttpsPort,
                RequireEncryption = entity.RequireEncryption,
                RequireRelyingPartyRegistration = entity.RequireRelyingPartyRegistration,
                SsoCookieLifetime = entity.SsoCookieLifetime
            };
        }

        public static Entities.Configuration.GlobalConfiguration ToEntity(this Models.Configuration.GlobalConfiguration model)
        {
            return new Entities.Configuration.GlobalConfiguration
            {
                SiteName = model.SiteName,
                IssuerUri = model.IssuerUri,
                IssuerContactEmail = model.IssuerContactEmail,
                DefaultHttpTokenType = model.DefaultHttpTokenType,
                DefaultWSTokenType = model.DefaultWSTokenType,
                DefaultTokenLifetime = model.DefaultTokenLifetime,
                MaximumTokenLifetime = model.MaximumTokenLifetime,
                EnableClientCertificateAuthentication = model.EnableClientCertificateAuthentication,
                EnforceUsersGroupMembership = model.EnforceUsersGroupMembership,
                HttpPort = model.HttpPort,
                HttpsPort = model.HttpsPort,
                RequireEncryption = model.RequireEncryption,
                RequireRelyingPartyRegistration = model.RequireRelyingPartyRegistration,
                SsoCookieLifetime = model.SsoCookieLifetime
            };
        }
        #endregion

        #region WSFederationConfiguration
        public static Models.Configuration.WSFederationConfiguration ToDomainModel(this Entities.Configuration.WSFederationConfiguration entity)
        {
            return new Models.Configuration.WSFederationConfiguration
            {
                AllowReplyTo = entity.AllowReplyTo,
                EnableAuthentication = entity.EnableAuthentication,
                Enabled = entity.Enabled,
                EnableFederation = entity.EnableFederation,
                EnableHrd = entity.EnableHrd,
                RequireReplyToWithinRealm = entity.RequireReplyToWithinRealm,
                RequireSslForReplyTo = entity.RequireSslForReplyTo
            };
        }

        public static Entities.Configuration.WSFederationConfiguration ToEntity(this Models.Configuration.WSFederationConfiguration model)
        {
            return new Entities.Configuration.WSFederationConfiguration
            {
                AllowReplyTo = model.AllowReplyTo,
                EnableAuthentication = model.EnableAuthentication,
                Enabled = model.Enabled,
                EnableFederation = model.EnableFederation,
                EnableHrd = model.EnableHrd,
                RequireReplyToWithinRealm = model.RequireReplyToWithinRealm,
                RequireSslForReplyTo = model.RequireSslForReplyTo
            };
        }
        #endregion

        #region KeyMaterialConfiguration
        public static Models.Configuration.KeyMaterialConfiguration ToDomainModel(this Entities.Configuration.KeyMaterialConfiguration entity)
        {
            var model = new Models.Configuration.KeyMaterialConfiguration();
            if (entity == null)
            {
                return model;
            }

            if (!string.IsNullOrWhiteSpace(entity.SigningCertificateName))
            {
                var cert = X509.LocalMachine.My.SubjectDistinguishedName.Find(entity.SigningCertificateName, false).FirstOrDefault();

                if (cert == null)
                {
                    throw new InvalidOperationException(string.Format(Core.Repositories.Resources.Mappings.SigningCertificateNotFoundException, entity.SigningCertificateName));
                }

                model.SigningCertificate = cert;
            }

            if (!string.IsNullOrWhiteSpace(entity.DecryptionCertificateName))
            {
                var cert = X509.LocalMachine.My.SubjectDistinguishedName.Find(entity.DecryptionCertificateName, false).FirstOrDefault();

                if (cert == null)
                {
                    throw new InvalidOperationException(string.Format(Core.Repositories.Resources.Mappings.DecryptionCertificateNotFoundException, entity.DecryptionCertificateName));
                }

                model.DecryptionCertificate = cert;
            }
            else
            {
                model.DecryptionCertificate = null;
            }

            model.SymmetricSigningKey = entity.SymmetricSigningKey;

            return model;
        }

        public static Entities.Configuration.KeyMaterialConfiguration ToEntity(this Models.Configuration.KeyMaterialConfiguration model)
        {
            var entity = new Entities.Configuration.KeyMaterialConfiguration();

            if (model.SigningCertificate != null)
            {
                entity.SigningCertificateName = model.SigningCertificate.Subject;
            }

            if (model.DecryptionCertificate != null)
            {
                entity.DecryptionCertificateName = model.DecryptionCertificate.Subject;
            }
            else
            {
                entity.DecryptionCertificateName = null;
            }

            entity.SymmetricSigningKey = model.SymmetricSigningKey;

            return entity;
        }
        #endregion

        #region WSTrustConfiguration
        public static Models.Configuration.WSTrustConfiguration ToDomainModel(this Entities.Configuration.WSTrustConfiguration entity)
        {
            return new Models.Configuration.WSTrustConfiguration
            {
                EnableClientCertificateAuthentication = entity.EnableClientCertificateAuthentication,
                Enabled = entity.Enabled,
                EnableDelegation = entity.EnableDelegation,
                EnableFederatedAuthentication = entity.EnableFederatedAuthentication,
                EnableMessageSecurity = entity.EnableMessageSecurity,
                EnableMixedModeSecurity = entity.EnableMixedModeSecurity
            };
        }

        public static Entities.Configuration.WSTrustConfiguration ToEntity(this Models.Configuration.WSTrustConfiguration model)
        {
            return new Entities.Configuration.WSTrustConfiguration
            {
                EnableClientCertificateAuthentication = model.EnableClientCertificateAuthentication,
                Enabled = model.Enabled,
                EnableDelegation = model.EnableDelegation,
                EnableFederatedAuthentication = model.EnableFederatedAuthentication,
                EnableMessageSecurity = model.EnableMessageSecurity,
                EnableMixedModeSecurity = model.EnableMixedModeSecurity
            };
        }
        #endregion

        #region FederationMetadataConfiguration
        public static Models.Configuration.FederationMetadataConfiguration ToDomainModel(this Entities.Configuration.FederationMetadataConfiguration entity)
        {
            return new Models.Configuration.FederationMetadataConfiguration
            {
                Enabled = entity.Enabled
            };
        }

        public static Entities.Configuration.FederationMetadataConfiguration ToEntity(this Models.Configuration.FederationMetadataConfiguration model)
        {
            return new Entities.Configuration.FederationMetadataConfiguration
            {
                Enabled = model.Enabled
            };
        }
        #endregion

        #region OAuth2Configuration
        public static Models.Configuration.OAuth2Configuration ToDomainModel(this Entities.Configuration.OAuth2Configuration entity)
        {
            return new Models.Configuration.OAuth2Configuration
            {
                Enabled = entity.Enabled,
                EnableImplicitFlow = entity.EnableImplicitFlow,
                EnableResourceOwnerFlow = entity.EnableResourceOwnerFlow,
                EnableConsent = entity.EnableConsent,
                EnableCodeFlow = entity.EnableCodeFlow
            };
        }

        public static Entities.Configuration.OAuth2Configuration ToEntity(this Models.Configuration.OAuth2Configuration model)
        {
            return new Entities.Configuration.OAuth2Configuration
            {
                Enabled = model.Enabled,
                EnableImplicitFlow = model.EnableImplicitFlow,
                EnableResourceOwnerFlow = model.EnableResourceOwnerFlow,
                EnableConsent = model.EnableConsent,
                EnableCodeFlow = model.EnableCodeFlow
            };
        }
        #endregion

        #region SimpleHttpConfiguration
        public static Models.Configuration.SimpleHttpConfiguration ToDomainModel(this Entities.Configuration.SimpleHttpConfiguration entity)
        {
            return new Models.Configuration.SimpleHttpConfiguration
            {
                Enabled = entity.Enabled
            };
        }

        public static Entities.Configuration.SimpleHttpConfiguration ToEntity(this Models.Configuration.SimpleHttpConfiguration model)
        {
            return new Entities.Configuration.SimpleHttpConfiguration
            {
                Enabled = model.Enabled
            };
        }
        #endregion

        #region DiagnosticsConfiguration
        public static Models.Configuration.DiagnosticsConfiguration ToDomainModel(this Entities.Configuration.DiagnosticsConfiguration entity)
        {
            return new Models.Configuration.DiagnosticsConfiguration
            {
                EnableFederationMessageTracing = entity.EnableFederationMessageTracing
            };
        }

        public static Entities.Configuration.DiagnosticsConfiguration ToEntity(this Models.Configuration.DiagnosticsConfiguration model)
        {
            return new Entities.Configuration.DiagnosticsConfiguration
            {
                EnableFederationMessageTracing = model.EnableFederationMessageTracing
            };
        }
        #endregion

        #region Relying Party
        public static RelyingParty ToDomainModel(this RelyingParties rpEntity)
        {
            var rp = new RelyingParty
            {
                Id = rpEntity.Id.ToString(),
                Name = rpEntity.Name,
                Enabled = rpEntity.Enabled,
                TokenLifeTime = rpEntity.TokenLifeTime,
                Realm = new Uri(rpEntity.Realm),
                ExtraData1 = rpEntity.ExtraData1,
                ExtraData2 = rpEntity.ExtraData2,
                ExtraData3 = rpEntity.ExtraData3
            };

            if (!string.IsNullOrWhiteSpace(rpEntity.ReplyTo))
            {
                rp.ReplyTo = new Uri(rpEntity.ReplyTo);
            }

            if (!string.IsNullOrWhiteSpace(rpEntity.EncryptingCertificate))
            {
                rp.EncryptingCertificate = new X509Certificate2(Convert.FromBase64String(rpEntity.EncryptingCertificate));
            }

            if (!string.IsNullOrWhiteSpace(rpEntity.SymmetricSigningKey))
            {
                rp.SymmetricSigningKey = Convert.FromBase64String(rpEntity.SymmetricSigningKey);
            }

            return rp;
        }

        public static RelyingParties ToEntity(this RelyingParty relyingParty)
        {
            var rpEntity = new RelyingParties
            {
                Name = relyingParty.Name,
                Enabled = relyingParty.Enabled,
                Realm = relyingParty.Realm.AbsoluteUri,
                TokenLifeTime = relyingParty.TokenLifeTime,
                ExtraData1 = relyingParty.ExtraData1,
                ExtraData2 = relyingParty.ExtraData2,
                ExtraData3 = relyingParty.ExtraData3,
            };

            if (!string.IsNullOrEmpty(relyingParty.Id))
            {
                rpEntity.Id = int.Parse(relyingParty.Id);
            }

            if (relyingParty.ReplyTo != null)
            {
                rpEntity.ReplyTo = relyingParty.ReplyTo.AbsoluteUri;
            }

            if (relyingParty.EncryptingCertificate != null)
            {
                rpEntity.EncryptingCertificate = Convert.ToBase64String(relyingParty.EncryptingCertificate.RawData);
            }

            if (relyingParty.SymmetricSigningKey != null && relyingParty.SymmetricSigningKey.Length != 0)
            {
                rpEntity.SymmetricSigningKey = Convert.ToBase64String(relyingParty.SymmetricSigningKey);
            }

            return rpEntity;
        }

        public static IEnumerable<RelyingParty> ToDomainModel(this List<RelyingParties> relyingParties)
        {
            return
                (from rp in relyingParties
                 select new RelyingParty
                 {
                     Id = rp.Id.ToString(),
                     Name = rp.Name,
                     Realm = new Uri(rp.Realm),
                     Enabled = rp.Enabled
                 }).ToList();
        }
        #endregion

        #region Client Certificates
        public static List<ClientCertificate> ToDomainModel(this List<ClientCertificates> entities)
        {
            return
                (from entity in entities
                 select new ClientCertificate
                 {
                     UserName = entity.UserName,
                     Thumbprint = entity.Thumbprint,
                     Description = entity.Description
                 }
                ).ToList();
        }
        #endregion

        #region Clients
        public static Models.Client ToDomainModel(this Entities.Client client)
        {
            return new Models.Client
            {
                ID = client.Id,
                ClientId = client.ClientId,
                ClientSecret = client.ClientSecret,
                Description = client.Description,
                Name = client.Name,
                RedirectUri = client.RedirectUri != null ? new Uri(client.RedirectUri) : null,
                AllowRefreshToken = client.AllowRefreshToken,
                AllowCodeFlow = client.AllowCodeFlow,
                AllowImplicitFlow = client.AllowImplicitFlow,
                AllowResourceOwnerFlow = client.AllowResourceOwnerFlow
            };
        }
        public static void UpdateEntity(this Models.Client client, Entities.Client target)
        {
            target.Id = client.ID;
            target.ClientId = client.ClientId;
            target.ClientSecret = client.ClientSecret;
            target.Description = client.Description;
            target.Name = client.Name;
            target.RedirectUri = client.RedirectUri != null ? client.RedirectUri.AbsoluteUri : null;
            target.AllowRefreshToken = client.AllowRefreshToken;
            target.AllowResourceOwnerFlow = client.AllowResourceOwnerFlow;
            target.AllowImplicitFlow = client.AllowImplicitFlow;
            target.AllowCodeFlow = client.AllowCodeFlow;
        }
        #endregion

        #region Delegation
        public static List<DelegationSetting> ToDomainModel(this List<Delegation> entities)
        {
            return
                (from entity in entities
                 select new DelegationSetting
                 {
                     UserName = entity.UserName,
                     Realm = new Uri(entity.Realm),
                     Description = entity.Description
                 }
                ).ToList();
        }
        #endregion

        #region IdentityProvider
        public static List<Models.IdentityProvider> ToDomainModel(this List<Entities.IdentityProvider> idps)
        {
            return new List<Models.IdentityProvider>(
                from idp in idps
                select new Models.IdentityProvider
                {
                    ID = idp.ID,
                    Name = idp.Name,
                    Enabled = idp.Enabled,
                    DisplayName = idp.DisplayName,
                    Type = (IdentityProviderTypes)idp.Type,
                    ShowInHrdSelection = idp.ShowInHrdSelection,
                    WSFederationEndpoint = idp.WSFederationEndpoint,
                    IssuerThumbprint = idp.IssuerThumbprint,
                    ClientID = idp.ClientID,
                    ClientSecret = idp.ClientSecret,
                    ProviderType = (OAuth2ProviderTypes?)idp.OAuth2ProviderType,
                });
        }

        public static Models.IdentityProvider ToDomainModel(this Entities.IdentityProvider idp)
        {
            if (idp == null)
            {
                return null;
            }

            return new Models.IdentityProvider
            {
                ID = idp.ID,
                Name = idp.Name,
                Enabled = idp.Enabled,
                DisplayName = idp.DisplayName,
                ShowInHrdSelection = idp.ShowInHrdSelection,
                Type = (IdentityProviderTypes)idp.Type,
                WSFederationEndpoint = idp.WSFederationEndpoint,
                IssuerThumbprint = idp.IssuerThumbprint,
                ClientID = idp.ClientID,
                ClientSecret = idp.ClientSecret,
                ProviderType = (OAuth2ProviderTypes?)idp.OAuth2ProviderType,
            };
        }

        public static Entities.IdentityProvider ToEntity(this Models.IdentityProvider idp)
        {
            if (idp == null)
            {
                return null;
            }

            var entity = new Entities.IdentityProvider();
            idp.UpdateEntity(entity);
            return entity;
        }

        public static void UpdateEntity(this Models.IdentityProvider idp, Entities.IdentityProvider entity)
        {
            if (idp == null || entity == null)
            {
                return;
            }

            entity.ID = idp.ID;
            entity.Name = idp.Name;
            entity.Enabled = idp.Enabled;
            entity.ShowInHrdSelection = idp.ShowInHrdSelection;
            entity.DisplayName = idp.DisplayName;
            entity.Type = (int)idp.Type;
            entity.WSFederationEndpoint = idp.WSFederationEndpoint;
            entity.IssuerThumbprint = idp.IssuerThumbprint;
            entity.ClientID = idp.ClientID;
            entity.ClientSecret = idp.ClientSecret;
            entity.OAuth2ProviderType = (int?)idp.ProviderType;
        }

        #endregion

        #region CodeToken
        public static Models.CodeToken ToDomainModel(this Entities.CodeToken token)
        {
            return new Models.CodeToken
            {
                ClientId = token.ClientId,
                Scope = token.Scope,
                UserName = token.UserName,
                Code = token.Code,
                Type = (CodeTokenType)token.Type,
                TimeStamp = token.TimeStamp
            };
        }
        #endregion
    }
}
