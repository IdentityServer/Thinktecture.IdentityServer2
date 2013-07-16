/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Net;
using System.Net.Http;
using Thinktecture.IdentityModel.Constants;

namespace Thinktecture.IdentityServer.Protocols.OAuth2
{
    [Serializable]
    public class TokenRequestValidationException : Exception
    {
        public string OAuthError { get; set; }

        public TokenRequestValidationException(string message, string oauthError)
        {
            Tracing.Error(message);
            OAuthError = oauthError;
        }

        public HttpResponseMessage CreateErrorResponse(HttpRequestMessage request)
        {
            Tracing.Information("Sending error response: " + OAuthError);

            return request.CreateErrorResponse(HttpStatusCode.BadRequest,
                string.Format("{{ \"{0}\": \"{1}\" }}", OAuth2Constants.Errors.Error, OAuthError));
        }
    }
}
