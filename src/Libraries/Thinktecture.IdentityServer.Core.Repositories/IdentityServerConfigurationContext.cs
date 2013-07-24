/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Data.Common;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;
using Thinktecture.IdentityServer.Repositories.Sql.Configuration;

namespace Thinktecture.IdentityServer.Repositories.Sql
{    
    public class IdentityServerConfigurationContext : DbContext
    {
        public DbSet<GlobalConfiguration> GlobalConfiguration { get; set; }
        public DbSet<WSFederationConfiguration> WSFederation { get; set; }
        public DbSet<KeyMaterialConfiguration> Keys { get; set; }
        public DbSet<WSTrustConfiguration> WSTrust { get; set; }
        public DbSet<FederationMetadataConfiguration> FederationMetadata { get; set; }
        public DbSet<OAuth2Configuration> OAuth2 { get; set; }
        public DbSet<AdfsIntegrationConfiguration> AdfsIntegration { get; set; }
        public DbSet<SimpleHttpConfiguration> SimpleHttp { get; set; }
        public DbSet<OpenIdConnectConfiguration> OpenIdConnect { get; set; }
        public DbSet<DiagnosticsConfiguration> Diagnostics { get; set; }
        
        public DbSet<ClientCertificates> ClientCertificates { get; set; }
        public DbSet<Delegation> Delegation { get; set; }
        public DbSet<RelyingParties> RelyingParties { get; set; }
        public DbSet<IdentityProvider> IdentityProviders { get; set; }
        public DbSet<Client> Clients { get; set; }
        public DbSet<CodeToken> CodeTokens { get; set; }
        public DbSet<OpenIdConnectClientEntity> OpenIdConnectClients { get; set; }

        public DbSet<StoredGrant> StoredGrants { get; set; }

        public static Func<IdentityServerConfigurationContext> FactoryMethod { get; set; }

        public IdentityServerConfigurationContext()
            : base("name=IdentityServerConfiguration")
        { }

        public IdentityServerConfigurationContext(DbConnection conn) : base(conn, true)
        {
        }

        public IdentityServerConfigurationContext(IDatabaseInitializer<IdentityServerConfigurationContext> initializer)
        {
            Database.SetInitializer(initializer);
        }

        public static IdentityServerConfigurationContext Get()
        {
            if (FactoryMethod != null) return FactoryMethod();

            return new IdentityServerConfigurationContext();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();
            modelBuilder.Entity<OpenIdConnectClientEntity>().ToTable("OpenIdConnectClients");
            modelBuilder.Entity<OpenIdConnectClientRedirectUri>().ToTable("OpenIdConnectClientsRedirectUris");

            base.OnModelCreating(modelBuilder);
        }
    }
}
