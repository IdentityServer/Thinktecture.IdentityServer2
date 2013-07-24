using System.Linq;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class OpenIdConnectClientIndexViewModel
    {
        private Repositories.IOpenIdConnectClientsRepository clientsRepository;
        public OpenIdConnectClientIndexInputModel[] Clients
        {
            get;
            private set;
        }

        public OpenIdConnectClientIndexViewModel(Repositories.IOpenIdConnectClientsRepository clientsRepository)
        {
            this.clientsRepository = clientsRepository;
            this.Clients = this.clientsRepository.GetAll().Select(x => new OpenIdConnectClientIndexInputModel { Name = x.Name, ClientId = x.ClientId }).ToArray();
        }
    }

    public class OpenIdConnectClientIndexInputModel
    {
        public string Name { get; set; }
        public string ClientId { get; set; }
        public bool Delete { get; set; }
    }

}