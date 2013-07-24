namespace Thinktecture.IdentityServer.Core.Repositories.Migrations.SqlServer
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class OIDC : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.OpenIdConnectConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Enabled = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.OpenIdConnectClients",
                c => new
                    {
                        ClientId = c.String(nullable: false, maxLength: 128),
                        ClientSecret = c.String(nullable: false),
                        ClientSecretType = c.Int(nullable: false),
                        Name = c.String(nullable: false),
                        Flow = c.Int(nullable: false),
                        AllowRefreshToken = c.Boolean(nullable: false),
                        AccessTokenLifetime = c.Int(nullable: false),
                        RefreshTokenLifetime = c.Int(nullable: false),
                        RequireConsent = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.ClientId);
            
            CreateTable(
                "dbo.OpenIdConnectClientsRedirectUris",
                c => new
                    {
                        ID = c.Int(nullable: false, identity: true),
                        RedirectUri = c.String(nullable: false),
                        OpenIdConnectClientEntity_ClientId = c.String(maxLength: 128),
                    })
                .PrimaryKey(t => t.ID)
                .ForeignKey("dbo.OpenIdConnectClients", t => t.OpenIdConnectClientEntity_ClientId)
                .Index(t => t.OpenIdConnectClientEntity_ClientId);
            
        }
        
        public override void Down()
        {
            DropIndex("dbo.OpenIdConnectClientsRedirectUris", new[] { "OpenIdConnectClientEntity_ClientId" });
            DropForeignKey("dbo.OpenIdConnectClientsRedirectUris", "OpenIdConnectClientEntity_ClientId", "dbo.OpenIdConnectClients");
            DropTable("dbo.OpenIdConnectClientsRedirectUris");
            DropTable("dbo.OpenIdConnectClients");
            DropTable("dbo.OpenIdConnectConfiguration");
        }
    }
}
