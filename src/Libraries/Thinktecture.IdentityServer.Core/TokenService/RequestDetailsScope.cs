/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System.IdentityModel;
using System.IdentityModel.Tokens;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityModel.Tokens;

namespace Thinktecture.IdentityServer.TokenService
{
    /// <summary>
    /// Summary description for PolicyScope
    /// </summary>
    public class RequestDetailsScope : Scope
    {
        public RequestDetails RequestDetails { get; protected set; }

        public RequestDetailsScope(RequestDetails details, SigningCredentials signingCredentials, bool requireEncryption)
            : base(details.Realm.Uri.AbsoluteUri, signingCredentials)
        {
            RequestDetails = details;
            
            if (RequestDetails.UsesEncryption)
            {
                EncryptingCredentials = new X509EncryptingCredentials(details.EncryptingCertificate);
            }

            if (RequestDetails.TokenType == TokenTypes.SimpleWebToken || RequestDetails.TokenType == TokenTypes.JsonWebToken)
            {
                if (details.RelyingPartyRegistration.SymmetricSigningKey != null && details.RelyingPartyRegistration.SymmetricSigningKey.Length > 0)
                {
                    SigningCredentials = new HmacSigningCredentials(details.RelyingPartyRegistration.SymmetricSigningKey);
                }
            }

            ReplyToAddress = RequestDetails.ReplyToAddress.AbsoluteUri;
            TokenEncryptionRequired = requireEncryption;
        }
    }
}