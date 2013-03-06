using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class Saml2Configuration : ProtocolConfiguration
    {
        [Display(Name = "Enable Sign-in", Description = "Enable sign-in via WS-Federation.")]
        public bool EnableAuthentication { get; set; }
        
        [Display(Name = "Enable Federation", Description = "Enable federated sign-in via WS-Federation (see Identity Providers).")]
        public bool EnableFederation { get; set; }
        
        [Display(Name = "Enable Home Realm Discovery", Description = "Enables the identity provider selection screen for federated sign-in.")]
        public bool EnableHrd { get; set; }

        [Display(Name = "Allow ReplyTo parameter", Description = "Allows specifying a WS-Federation replyto parameter. Otherwise this parameter is always ignored.")]
        public bool AllowReplyTo { get; set; }
        
        [Display(Name = "Require ReplyTo within Realm", Description = "Makes sure that the replyto parameter is a sub-URL of the realm.")]
        public Boolean RequireReplyToWithinRealm { get; set; }
        
        [Display(Name = "Require SSL", Description = "Enforces SSL for the replyto address. Should always be enabled.")]
        public Boolean RequireSslForReplyTo { get; set; }
    }
}
