namespace Thinktecture.IdentityServer.Core.Repositories.Migrations
{
    using System.Data.Entity.Migrations;
    
    public partial class CleanupIdentityProviderOAuthInfo : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.IdentityProvider", "OAuth2ProviderType", c => c.Int());
            DropColumn("dbo.IdentityProvider", "AuthorizationUrl");
            DropColumn("dbo.IdentityProvider", "ProfileType");
            DropColumn("dbo.IdentityProvider", "CustomProfileType");
        }
        
        public override void Down()
        {
            AddColumn("dbo.IdentityProvider", "CustomProfileType", c => c.String(maxLength: 4000));
            AddColumn("dbo.IdentityProvider", "ProfileType", c => c.Int());
            AddColumn("dbo.IdentityProvider", "AuthorizationUrl", c => c.String(maxLength: 4000));
            DropColumn("dbo.IdentityProvider", "OAuth2ProviderType");
        }
    }
}
