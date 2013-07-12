/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models
{
    public class CodeToken
    {
        public string Code { get; set; }

        [Display(ResourceType = typeof(Resources.Models.CodeToken), Name = "ClientId")]
        public int ClientId { get; set; }

        [Display(ResourceType = typeof(Resources.Models.CodeToken), Name = "UserName")]
        public string UserName { get; set; }

        [Display(ResourceType = typeof(Resources.Models.CodeToken), Name = "Scope")]
        public string Scope { get; set; }

        public CodeTokenType Type { get; set; }

        [Display(ResourceType = typeof(Resources.Models.CodeToken), Name = "TimeStamp")]
        public DateTime TimeStamp { get; set; }
    }
}
