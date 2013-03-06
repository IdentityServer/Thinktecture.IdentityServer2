namespace Thinktecture.IdentityServer.Core.Repositories.Migrations
{
    using System.Data.Entity.Migrations;
    
    public partial class UpdatedClientConfig : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Client", "NativeClient", c => c.Boolean(nullable: false));
            AddColumn("dbo.Client", "AllowImplicitFlow", c => c.Boolean(nullable: false));
            AddColumn("dbo.Client", "AllowResourceOwnerFlow", c => c.Boolean(nullable: false));
            AddColumn("dbo.Client", "AllowCodeFlow", c => c.Boolean(nullable: false));
        }
        
        public override void Down()
        {
            DropColumn("dbo.Client", "AllowCodeFlow");
            DropColumn("dbo.Client", "AllowResourceOwnerFlow");
            DropColumn("dbo.Client", "AllowImplicitFlow");
            DropColumn("dbo.Client", "NativeClient");
        }
    }
}
