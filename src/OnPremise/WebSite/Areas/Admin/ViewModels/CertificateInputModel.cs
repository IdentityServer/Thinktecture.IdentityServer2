using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public abstract class CertificateInputModel : IValidatableObject
    {
        public abstract HttpPostedFileBase File { get; }
        public bool? RemoveCert { get; set; }

        bool certProcessed;
        X509Certificate2 cert;
        public X509Certificate2 Cert
        {
            get
            {
                ProcessCert();
                return cert;
            }
        }

        private void ProcessCert()
        {
            if (certProcessed) return;
            certProcessed = true;

            if (File != null && File.ContentLength > 0)
            {
                using (var ms = new MemoryStream())
                {
                    File.InputStream.CopyTo(ms);
                    var bytes = ms.ToArray();
                    var val = new X509Certificate2(bytes);
                    cert = val;
                }
            }
        }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            var errors = new List<ValidationResult>();
            try
            {
                ProcessCert();
            }
            catch
            {
                errors.Add(new ValidationResult(Resources.CertificateInputModel.ErrorProcessingCertificate, new string[]{"EncryptingCertificate"}));
            }
            return errors;
        }
    }
}