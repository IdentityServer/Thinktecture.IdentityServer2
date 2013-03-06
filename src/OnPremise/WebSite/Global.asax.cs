using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.Data.Entity;
using System.Security.Claims;
using System.Web.Helpers;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Repositories.Sql;

namespace Thinktecture.IdentityServer.Web
{
    public class MvcApplication : System.Web.HttpApplication
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IRelyingPartyRepository RelyingPartyRepository { get; set; }

       

        protected void Application_Start()
        {
            // create empty config database if it not exists
            Database.SetInitializer(new ConfigurationDatabaseInitializer());
            
            // set the anti CSRF for name (that's a unqiue claim in our system)
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.Name;

            // setup MEF
            SetupCompositionContainer();
            Container.Current.SatisfyImportsOnce(this);

            AreaRegistration.RegisterAllAreas();

            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes, ConfigurationRepository, UserRepository);
            ProtocolConfig.RegisterProtocols(GlobalConfiguration.Configuration, RouteTable.Routes, ConfigurationRepository, UserRepository, RelyingPartyRepository);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }

        private void SetupCompositionContainer()
        {
            Container.Current = new CompositionContainer(new RepositoryExportProvider());
        }
    }
}