/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class DiagnosticsConfiguration
    {
        [Display(ResourceType = typeof (Resources.Models.Configuration.DiagnosticsConfiguration), Name = "EnableFederationMessageTracing", Description = "EnableFederationMessageTracingDescription")]
        public Boolean EnableFederationMessageTracing { get; set; }
    }
}
