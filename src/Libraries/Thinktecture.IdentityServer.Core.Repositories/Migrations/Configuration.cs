using Thinktecture.IdentityServer.Repositories.Sql.Configuration;

namespace Thinktecture.IdentityServer.Core.Repositories.Migrations
{
    using System.Data.Entity.Migrations;

    internal sealed class Configuration : DbMigrationsConfiguration<Thinktecture.IdentityServer.Repositories.Sql.IdentityServerConfigurationContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = true;
        }

        protected override void Seed(Thinktecture.IdentityServer.Repositories.Sql.IdentityServerConfigurationContext context)
        {
           // context.Saml2.AddOrUpdate(new Saml2Configuration(){EnableAuthentication = true,Enabled = true,EnableFederation = true,EnableHrd = true,RequireReplyToWithinRealm = true,Id = 1});
            //context.Saml2Metadata.AddOrUpdate(new Saml2MetadataConfiguration{Enabled = true,Id=1});
            //  This method will be called after migrating to the latest version.

            //  You can use the DbSet<T>.AddOrUpdate() helper extension method 
            //  to avoid creating duplicate seed data. E.g.
            //
            //    context.People.AddOrUpdate(
            //      p => p.FullName,
            //      new Person { FullName = "Andrew Peters" },
            //      new Person { FullName = "Brice Lambson" },
            //      new Person { FullName = "Rowan Miller" }
            //    );
            //
        }
    }
}
