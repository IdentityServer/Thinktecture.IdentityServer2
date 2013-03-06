namespace Thinktecture.IdentityServer.Core.Repositories.Migrations
{
    using System.Data.Entity.Migrations;
    
    public partial class UpdatedOAuth2Config : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.OAuth2Configuration", "EnableConsent", c => c.Boolean(nullable: false));
            DropColumn("dbo.OAuth2Configuration", "RequireClientAuthentication");
        }
        
        public override void Down()
        {
            AddColumn("dbo.OAuth2Configuration", "RequireClientAuthentication", c => c.Boolean(nullable: false));
            DropColumn("dbo.OAuth2Configuration", "EnableConsent");
        }
    }
}
