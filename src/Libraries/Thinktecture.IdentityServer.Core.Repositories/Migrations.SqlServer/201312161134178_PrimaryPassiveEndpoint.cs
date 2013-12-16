namespace Thinktecture.IdentityServer.Core.Repositories.Migrations.SqlServer
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class PrimaryPassiveEndpoint : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.FederationMetadataConfiguration", "PrimaryPassiveEndpoint", c => c.Int());
        }
        
        public override void Down()
        {
            DropColumn("dbo.FederationMetadataConfiguration", "PrimaryPassiveEndpoint");
        }
    }
}
