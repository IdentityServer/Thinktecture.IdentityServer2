using System;
using System.Collections.Generic;
using System.Security.Claims;
using Thinktecture.IdentityServer.Protocols.OpenIdConnect;

public class AccessToken : OidcToken
{
    public IEnumerable<string> Scopes { get; set; }
    public string Subject { get; set; }
    public string ClientId { get; set; }

    protected override List<Claim> CreateClaims()
    {
        if (Scopes == null)
        {
            throw new InvalidOperationException("Scopes is empty");
        }
        if (string.IsNullOrWhiteSpace(Subject))
        {
            throw new InvalidOperationException("Subject is empty");
        }
        if (string.IsNullOrWhiteSpace(ClientId))
        {
            throw new InvalidOperationException("ClientId is empty");
        }

        var claims = base.CreateClaims();

        foreach (var scope in Scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        claims.Add(new Claim(OidcConstants.ClaimTypes.Subject, Subject));
        claims.Add(new Claim("client_id", ClientId));

        return claims;
    }
}