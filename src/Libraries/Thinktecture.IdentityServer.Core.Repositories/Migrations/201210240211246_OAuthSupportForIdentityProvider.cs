namespace Thinktecture.IdentityServer.Core.Repositories.Migrations
{
    using System.Data.Entity.Migrations;
    
    public partial class OAuthSupportForIdentityProvider : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.IdentityProvider", "ClientID", c => c.String(maxLength: 4000));
            AddColumn("dbo.IdentityProvider", "ClientSecret", c => c.String(maxLength: 4000));
            AddColumn("dbo.IdentityProvider", "AuthorizationUrl", c => c.String(maxLength: 4000));
            AddColumn("dbo.IdentityProvider", "ProfileType", c => c.Int());
            AddColumn("dbo.IdentityProvider", "CustomProfileType", c => c.String(maxLength: 4000));
            DropColumn("dbo.IdentityProvider", "Type");
            AddColumn("dbo.IdentityProvider", "Type", c => c.Int(nullable: false, defaultValue:1));
        }
        
        public override void Down()
        {
            DropColumn("dbo.IdentityProvider", "Type");
            AddColumn("dbo.IdentityProvider", "Type", c => c.String(nullable: false, maxLength: 4000, defaultValue:"WS*"));
            DropColumn("dbo.IdentityProvider", "CustomProfileType");
            DropColumn("dbo.IdentityProvider", "ProfileType");
            DropColumn("dbo.IdentityProvider", "AuthorizationUrl");
            DropColumn("dbo.IdentityProvider", "ClientSecret");
            DropColumn("dbo.IdentityProvider", "ClientID");
        }
    }
}
