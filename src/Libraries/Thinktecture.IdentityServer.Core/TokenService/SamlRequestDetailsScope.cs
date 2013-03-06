/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityModel.Tokens;
using Microsoft.IdentityModel;
using Microsoft.IdentityModel.SecurityTokenService;

namespace Thinktecture.IdentityServer.TokenService
{
    /// <summary>
    /// Summary description for PolicyScope
    /// </summary>
    public sealed class SamlRequestDetailsScope : Scope
    {
        public SamlRequestDetails RequestDetails { get; protected set; }

        public SamlRequestDetailsScope(SamlRequestDetails details, EncryptingCredentials signingCredentials, bool requireEncryption)
            : base(details.Realm.Uri.AbsoluteUri, signingCredentials)
        {
            RequestDetails = details;

            if (RequestDetails.UsesEncryption)
            {
                EncryptingCredentials = new X509EncryptingCredentials(details.EncryptingCertificate);
            }

            if (RequestDetails.TokenType == TokenTypes.SimpleWebToken || RequestDetails.TokenType == TokenTypes.JsonWebToken)
            {
                SigningCredentials = new HmacSigningCredentials(details.RelyingPartyRegistration.SymmetricSigningKey);
            }

            ReplyToAddress = RequestDetails.ReplyToAddress.AbsoluteUri;
            TokenEncryptionRequired = requireEncryption;
        }
    }
}