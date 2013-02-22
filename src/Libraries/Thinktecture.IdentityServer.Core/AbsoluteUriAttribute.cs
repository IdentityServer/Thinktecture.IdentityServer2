using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer
{
    public class AbsoluteUriAttribute : ValidationAttribute
    {
        public AbsoluteUriAttribute()
        {
            this.ErrorMessageResourceName = "UriMustBeAbsolute";
            this.ErrorMessageResourceType = typeof (Resources.AbsoluteUriAttribute);
        }
        
        public override bool IsValid(object value)
        {
            if (value == null) return true;

            Uri uri = value as Uri;
            if (uri == null)
            {
                var s = value as string;
                if (s != null)
                {
                    if (!Uri.TryCreate(s, UriKind.Absolute, out uri))
                    {
                        return false;
                    }
                }
                else
                {
                    throw new Exception("AbsoluteUriAttribute applied to a value that is not a Uri or a string.");
                }
            }
            return uri.IsAbsoluteUri;
        }
    }
}
