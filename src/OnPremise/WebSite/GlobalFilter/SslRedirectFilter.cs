/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Web.Mvc;

namespace Thinktecture.IdentityServer.Web.GlobalFilter
{
    public class SslRedirectFilter : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (!filterContext.HttpContext.Request.IsSecureConnection)
            {
                filterContext.Result = new RedirectResult(
                    GetAbsoluteUri(filterContext.HttpContext.Request.Url).AbsoluteUri,
                    true);
            }
        }

        private Uri GetAbsoluteUri(Uri uriFromCaller)
        {
            UriBuilder builder = new UriBuilder(Uri.UriSchemeHttps, uriFromCaller.Host);
            builder.Path = uriFromCaller.GetComponents(UriComponents.Path, UriFormat.Unescaped);

            string query = uriFromCaller.GetComponents(UriComponents.Query, UriFormat.UriEscaped);
            if (query.Length > 0)
            {
                string uriWithoutQuery = builder.Uri.AbsoluteUri;
                string absoluteUri = string.Format("{0}?{1}", uriWithoutQuery, query);
                return new Uri(absoluteUri, UriKind.Absolute);
            }
            else
            {
                return builder.Uri;
            }
        }
    }
}