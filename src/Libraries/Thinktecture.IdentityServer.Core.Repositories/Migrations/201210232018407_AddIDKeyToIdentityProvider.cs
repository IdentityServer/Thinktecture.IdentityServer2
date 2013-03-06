namespace Thinktecture.IdentityServer.Core.Repositories.Migrations
{
    using System.Data.Entity.Migrations;
    
    public partial class AddIDKeyToIdentityProvider : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.IdentityProvider", "ID", c => c.Int(nullable: false, identity: true));
            DropPrimaryKey("dbo.IdentityProvider", new[] { "Name" });
            AddPrimaryKey("dbo.IdentityProvider", "ID");
        }
        
        public override void Down()
        {
            DropPrimaryKey("dbo.IdentityProvider", new[] { "ID" });
            AddPrimaryKey("dbo.IdentityProvider", "Name");
            DropColumn("dbo.IdentityProvider", "ID");
        }
    }
}
