/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace Thinktecture.IdentityServer.Models.Configuration
{
    public class KeyMaterialConfiguration
    {
        [Display(ResourceType = typeof (Resources.Models.Configuration.KeyMaterialConfiguration), Name = "SigningCertificate", Description = "SigningCertificateDescription")]
        [Required]
        public X509Certificate2 SigningCertificate { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.KeyMaterialConfiguration), Name = "DecryptionCertificate", Description = "DecryptionCertificateDescription")]
        public X509Certificate2 DecryptionCertificate { get; set; }

        //[Display(Name = "RSA Signing Key", Description = "The RSA key to sign outgoing JWT tokens")]
        //public RSA RSASigningKey { get; set; }

        [Display(ResourceType = typeof (Resources.Models.Configuration.KeyMaterialConfiguration), Name = "SymmetricSigningKey", Description = "SymmetricSigningKeyDescription")]
        [Required]
        public string SymmetricSigningKey { get; set; }
    }
}
