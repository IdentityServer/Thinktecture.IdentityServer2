/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;

namespace Thinktecture.IdentityServer.Web.ViewModels
{
    public class InitialConfigurationModel
    {
        [Display(Name = "SiteName", ResourceType = typeof(Resources.InitialConfigurationModel))]
        [Required]
        public string SiteName { get; set; }

        [Display(Name = "IssuerUri", ResourceType = typeof(Resources.InitialConfigurationModel))]
        [Required]
        public string IssuerUri { get; set; }

        [Display(Name = "SigningCertificate", ResourceType = typeof(Resources.InitialConfigurationModel))]
        [Required]
        public string SigningCertificate { get; set; }

        public List<string> AvailableCertificates { get; set; }

        [Display(Name = "CreateDefaultAccounts", ResourceType = typeof(Resources.InitialConfigurationModel))]
        public bool CreateDefaultAccounts { get; set; }

        [Display(Name = "UserName", ResourceType = typeof(Resources.InitialConfigurationModel))]
        public string UserName { get; set; }

        [Display(Name = "Password", ResourceType = typeof(Resources.InitialConfigurationModel))]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public List<SelectListItem> AvailableCertificatesList
        {
            get
            {
                if (AvailableCertificates != null)
                {
                    return
                        (from c in AvailableCertificates
                         select new SelectListItem
                         {
                             Text = c,
                             Value = c
                         })
                        .ToList();
                }

                return null;
            }
        }
    }
}