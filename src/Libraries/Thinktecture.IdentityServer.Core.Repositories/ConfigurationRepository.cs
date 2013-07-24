using System.Linq;
using Entities = Thinktecture.IdentityServer.Repositories.Sql;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    public class ConfigurationRepository : IConfigurationRepository
    {
        public virtual bool SupportsWriteAccess
        {
            get { return true; }
        }

        public virtual Models.Configuration.GlobalConfiguration Global
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.GlobalConfiguration.First<Entities.Configuration.GlobalConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.GlobalConfiguration.First<Entities.Configuration.GlobalConfiguration>();
                    entities.GlobalConfiguration.Remove(entity);

                    entities.GlobalConfiguration.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        public virtual Models.Configuration.DiagnosticsConfiguration Diagnostics
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.Diagnostics.First<Entities.Configuration.DiagnosticsConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.Diagnostics.First<Entities.Configuration.DiagnosticsConfiguration>();
                    entities.Diagnostics.Remove(entity);

                    entities.Diagnostics.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        public virtual Models.Configuration.KeyMaterialConfiguration Keys
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.Keys.FirstOrDefault<Entities.Configuration.KeyMaterialConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.Keys.FirstOrDefault<Entities.Configuration.KeyMaterialConfiguration>();

                    if (entity != null)
                    {
                        entities.Keys.Remove(entity);
                    }

                    entities.Keys.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        public virtual Models.Configuration.WSFederationConfiguration WSFederation
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.WSFederation.First<Entities.Configuration.WSFederationConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.WSFederation.First<Entities.Configuration.WSFederationConfiguration>();
                    entities.WSFederation.Remove(entity);

                    entities.WSFederation.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        public virtual Models.Configuration.FederationMetadataConfiguration FederationMetadata
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.FederationMetadata.First<Entities.Configuration.FederationMetadataConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.FederationMetadata.First<Entities.Configuration.FederationMetadataConfiguration>();
                    entities.FederationMetadata.Remove(entity);

                    entities.FederationMetadata.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        public virtual Models.Configuration.WSTrustConfiguration WSTrust
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.WSTrust.First<Entities.Configuration.WSTrustConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.WSTrust.First<Entities.Configuration.WSTrustConfiguration>();
                    entities.WSTrust.Remove(entity);

                    entities.WSTrust.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        public virtual Models.Configuration.OAuth2Configuration OAuth2
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.OAuth2.First<Entities.Configuration.OAuth2Configuration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.OAuth2.First<Entities.Configuration.OAuth2Configuration>();
                    entities.OAuth2.Remove(entity);

                    entities.OAuth2.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        public virtual Models.Configuration.SimpleHttpConfiguration SimpleHttp
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.SimpleHttp.First<Entities.Configuration.SimpleHttpConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.SimpleHttp.First<Entities.Configuration.SimpleHttpConfiguration>();
                    entities.SimpleHttp.Remove(entity);

                    entities.SimpleHttp.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }

        // todo: wire up with DB
        public Models.Configuration.AdfsIntegrationConfiguration AdfsIntegration
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.AdfsIntegration.First<Entities.Configuration.AdfsIntegrationConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.AdfsIntegration.First<Entities.Configuration.AdfsIntegrationConfiguration>();
                    entities.AdfsIntegration.Remove(entity);

                    entities.AdfsIntegration.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }


        public Models.Configuration.OpenIdConnectConfiguration OpenIdConnect
        {
            get
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.OpenIdConnect.First<Entities.Configuration.OpenIdConnectConfiguration>();
                    return entity.ToDomainModel();
                }
            }
            set
            {
                using (var entities = IdentityServerConfigurationContext.Get())
                {
                    var entity = entities.OpenIdConnect.First<Entities.Configuration.OpenIdConnectConfiguration>();
                    entities.OpenIdConnect.Remove(entity);

                    entities.OpenIdConnect.Add(value.ToEntity());
                    entities.SaveChanges();
                }
            }
        }
    }
}
