/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace Thinktecture.IdentityServer.Models
{
    public class RelyingParty
    {
        [Required]
        [UIHint("HiddenInput")]
        public string Id { get; set; }
        
        [Display(ResourceType = typeof (Resources.Models.RelyingParty), Name = "Enabled", Description = "EnabledDescription")]
        public bool Enabled { get; set; }
        
        [Required]
        [Display(ResourceType = typeof (Resources.Models.RelyingParty), Name = "Name", Description = "NameDescription")]
        public string Name { get; set; }
        
        [Required]
        [Display(ResourceType = typeof (Resources.Models.RelyingParty), Name = "Realm", Description = "RealmDescription")]
        [AbsoluteUri]
        public Uri Realm { get; set; }

        [Required]
        [Display(ResourceType = typeof (Resources.Models.RelyingParty), Name = "TokenLifeTime", Description = "TokenLifeTimeDescription")]
        public int TokenLifeTime { get; set; }

        [Display(ResourceType = typeof (Resources.Models.RelyingParty), Name = "ReplyTo", Description = "ReplyToDescription")]
        [AbsoluteUri]
        public Uri ReplyTo { get; set; }

        [Display(Order=10002, ResourceType = typeof (Resources.Models.RelyingParty), Name = "EncryptingCertificate", Description = "EncryptingCertificateDescription")]
        public X509Certificate2 EncryptingCertificate { get; set; }

        [Display(Order = 10001, ResourceType = typeof (Resources.Models.RelyingParty), Name = "SymmetricSigningKey", Description = "SymmetricSigningKeyDescription")]
        public byte[] SymmetricSigningKey { get; set; }

        [Display(ResourceType = typeof (Resources.Models.RelyingParty), Name = "ExtraData1", Description = "ExtraData1Description")]
        public string ExtraData1 { get; set; }

        [Display(ResourceType = typeof(Resources.Models.RelyingParty), Name = "ExtraData2", Description = "ExtraData2Description")]
        public string ExtraData2 { get; set; }

        [Display(ResourceType = typeof(Resources.Models.RelyingParty), Name = "ExtraData3", Description = "ExtraData3Description")]
        public string ExtraData3 { get; set; }
    }
}