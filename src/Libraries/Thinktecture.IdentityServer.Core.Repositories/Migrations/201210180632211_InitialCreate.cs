namespace Thinktecture.IdentityServer.Core.Repositories.Migrations
{
    using System.Data.Entity.Migrations;
    
    public partial class InitialCreate : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.GlobalConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        SiteName = c.String(nullable: false, maxLength: 4000),
                        IssuerUri = c.String(nullable: false, maxLength: 4000),
                        IssuerContactEmail = c.String(nullable: false, maxLength: 4000),
                        DefaultWSTokenType = c.String(nullable: false, maxLength: 4000),
                        DefaultHttpTokenType = c.String(nullable: false, maxLength: 4000),
                        DefaultTokenLifetime = c.Int(nullable: false),
                        MaximumTokenLifetime = c.Int(nullable: false),
                        SsoCookieLifetime = c.Int(nullable: false),
                        RequireEncryption = c.Boolean(nullable: false),
                        RequireRelyingPartyRegistration = c.Boolean(nullable: false),
                        EnableClientCertificateAuthentication = c.Boolean(nullable: false),
                        EnforceUsersGroupMembership = c.Boolean(nullable: false),
                        HttpPort = c.Int(nullable: false),
                        HttpsPort = c.Int(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.WSFederationConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Enabled = c.Boolean(nullable: false),
                        EnableAuthentication = c.Boolean(nullable: false),
                        EnableFederation = c.Boolean(nullable: false),
                        EnableHrd = c.Boolean(nullable: false),
                        AllowReplyTo = c.Boolean(nullable: false),
                        RequireReplyToWithinRealm = c.Boolean(nullable: false),
                        RequireSslForReplyTo = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.KeyMaterialConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        SigningCertificateName = c.String(maxLength: 4000),
                        DecryptionCertificateName = c.String(maxLength: 4000),
                        RSASigningKey = c.String(maxLength: 4000),
                        SymmetricSigningKey = c.String(maxLength: 4000),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.WSTrustConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Enabled = c.Boolean(nullable: false),
                        EnableMessageSecurity = c.Boolean(nullable: false),
                        EnableMixedModeSecurity = c.Boolean(nullable: false),
                        EnableClientCertificateAuthentication = c.Boolean(nullable: false),
                        EnableFederatedAuthentication = c.Boolean(nullable: false),
                        EnableDelegation = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.FederationMetadataConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Enabled = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);

            CreateTable(
                "dbo.Saml2MetadataConfiguration",
                c => new
                {
                    Id = c.Int(nullable: false, identity: true),
                    Enabled = c.Boolean(nullable: false),
                })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.OAuth2Configuration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Enabled = c.Boolean(nullable: false),
                        RequireClientAuthentication = c.Boolean(nullable: false),
                        EnableResourceOwnerFlow = c.Boolean(nullable: false),
                        EnableImplicitFlow = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.SimpleHttpConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Enabled = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.DiagnosticsConfiguration",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        EnableFederationMessageTracing = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.ClientCertificates",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        UserName = c.String(nullable: false, maxLength: 4000),
                        Thumbprint = c.String(nullable: false, maxLength: 4000),
                        Description = c.String(nullable: false, maxLength: 4000),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.Delegation",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        UserName = c.String(nullable: false, maxLength: 4000),
                        Realm = c.String(nullable: false, maxLength: 4000),
                        Description = c.String(maxLength: 4000),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.RelyingParties",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Name = c.String(nullable: false, maxLength: 4000),
                        Enabled = c.Boolean(nullable: false),
                        Realm = c.String(nullable: false, maxLength: 4000),
                        TokenLifeTime = c.Int(nullable: false),
                        ReplyTo = c.String(maxLength: 4000),
                        EncryptingCertificate = c.String(),
                        SymmetricSigningKey = c.String(maxLength: 4000),
                        ExtraData1 = c.String(maxLength: 4000),
                        ExtraData2 = c.String(maxLength: 4000),
                        ExtraData3 = c.String(maxLength: 4000),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.IdentityProvider",
                c => new
                    {
                        Name = c.String(nullable: false, maxLength: 4000),
                        DisplayName = c.String(nullable: false, maxLength: 4000),
                        Type = c.String(nullable: false, maxLength: 4000),
                        ShowInHrdSelection = c.Boolean(nullable: false),
                        WSFederationEndpoint = c.String(maxLength: 4000),
                        IssuerThumbprint = c.String(maxLength: 4000),
                        Enabled = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Name);
            
            CreateTable(
                "dbo.Client",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Name = c.String(nullable: false, maxLength: 4000),
                        Description = c.String(nullable: false, maxLength: 4000),
                        ClientId = c.String(nullable: false, maxLength: 4000),
                        ClientSecret = c.String(nullable: false, maxLength: 4000),
                        RedirectUri = c.String(maxLength: 4000),
                    })
                .PrimaryKey(t => t.Id);
            
        }
        
        public override void Down()
        {
            DropTable("dbo.Client");
            DropTable("dbo.IdentityProvider");
            DropTable("dbo.RelyingParties");
            DropTable("dbo.Delegation");
            DropTable("dbo.ClientCertificates");
            DropTable("dbo.DiagnosticsConfiguration");
            DropTable("dbo.SimpleHttpConfiguration");
            DropTable("dbo.OAuth2Configuration");
            DropTable("dbo.FederationMetadataConfiguration");
            DropTable("dbo.Saml2MetadataConfiguration");
            DropTable("dbo.WSTrustConfiguration");
            DropTable("dbo.KeyMaterialConfiguration");
            DropTable("dbo.WSFederationConfiguration");
            DropTable("dbo.GlobalConfiguration");
        }
    }
}
