/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models
{
    public class DelegationSetting
    {
        [Required]
        [Display(ResourceType = typeof (Resources.Models.DelegationSetting), Name = "Description", Description = "DescriptionDescription")]
        public string Description { get; set; }

        [Required]
        [Display(ResourceType = typeof (Resources.Models.DelegationSetting), Name = "UserName", Description = "UserNameDescription")]
        public string UserName { get; set; }

        [Required]
        [Display(ResourceType = typeof (Resources.Models.DelegationSetting), Name = "Realm", Description = "RealmDescription")]
        [AbsoluteUri]
        public Uri Realm { get; set; }
    }
}
