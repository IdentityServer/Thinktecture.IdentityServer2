/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Configuration;
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
        public DbSet<Saml2Configuration> Saml2 { get; set; }
        public DbSet<KeyMaterialConfiguration> Keys { get; set; }
        public DbSet<WSTrustConfiguration> WSTrust { get; set; }
        public DbSet<FederationMetadataConfiguration> FederationMetadata { get; set; }
        public DbSet<Saml2MetadataConfiguration> Saml2Metadata { get; set; }
        public DbSet<OAuth2Configuration> OAuth2 { get; set; }
        public DbSet<SimpleHttpConfiguration> SimpleHttp { get; set; }
        public DbSet<DiagnosticsConfiguration> Diagnostics { get; set; }
        
        public DbSet<ClientCertificates> ClientCertificates { get; set; }
        public DbSet<Delegation> Delegation { get; set; }
        public DbSet<RelyingParties> RelyingParties { get; set; }
        public DbSet<IdentityProvider> IdentityProviders { get; set; }
        public DbSet<Client> Clients { get; set; }

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

            var cs = ConfigurationManager.ConnectionStrings["IdentityServerConfiguration"].ConnectionString;
            var conn = Database.DefaultConnectionFactory.CreateConnection(cs);
            return new IdentityServerConfigurationContext(conn);
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();
            base.OnModelCreating(modelBuilder);
        }
    }
}
