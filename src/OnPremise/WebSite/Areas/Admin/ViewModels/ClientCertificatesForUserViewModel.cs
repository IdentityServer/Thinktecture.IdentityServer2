using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class ClientCertificatesForUserViewModel
    {
        private Repositories.IClientCertificatesRepository clientCertificatesRepository;
        private Repositories.IUserManagementRepository userManagementRepository;
        
        [Required]
        public string UserName { get; set; }
        public IEnumerable<ClientCertificate> Certificates { get; set; }

        public ClientCertificate NewCertificate { get; set; }

        public bool IsNew
        {
            get
            {
                return this.UserName == null;
            }
        }

        public IEnumerable<SelectListItem> AllUserNames { get; set; }

        public ClientCertificatesForUserViewModel(IClientCertificatesRepository clientCertificatesRepository, IUserManagementRepository userManagementRepository, string username)
        {
            this.clientCertificatesRepository = clientCertificatesRepository;
            this.userManagementRepository = userManagementRepository;
            var allnames =
                userManagementRepository.GetUsers()
                .Select(x => new SelectListItem
                {
                    Text = x
                }).ToList();
            allnames.Insert(0, new SelectListItem { Text = Resources.ClientCertificatesForUserViewModel.ChooseItem, Value = "" });
            this.AllUserNames = allnames;
            
            this.UserName = username;
            NewCertificate = new ClientCertificate { UserName = username };
            if (!IsNew)
            {
                var certs =
                        this.clientCertificatesRepository
                        .GetClientCertificatesForUser(this.UserName)
                            .ToArray();
                this.Certificates = certs;
            }
            else
            {
                this.Certificates = new ClientCertificate[0];
            }
        }
    }
}