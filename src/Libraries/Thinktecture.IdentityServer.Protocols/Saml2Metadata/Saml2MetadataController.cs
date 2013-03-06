using System.ComponentModel.Composition;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Helper;
using Thinktecture.IdentityServer.Protocols.Saml2Metadata;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Protocols.SAML2Metadata
{
    public class Saml2MetadataController : Controller
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public ICacheRepository CacheRepository { get; set; }

        public Saml2MetadataController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public Saml2MetadataController(IConfigurationRepository configurationRepository, ICacheRepository cacheRepository)
        {
            ConfigurationRepository = configurationRepository;
            CacheRepository = cacheRepository;
        }

        public ActionResult Generate()
        {
            if (ConfigurationRepository.Saml2Metadata.Enabled)
            {
                return Cache.ReturnFromCache<ActionResult>(CacheRepository, Constants.CacheKeys.SAML2PMetadata, 1, () =>
                    {
                        var endpoints = Endpoints.Create(HttpContext.Request.Headers["Host"],HttpContext.Request.ApplicationPath,ConfigurationRepository.Global.HttpPort,ConfigurationRepository.Global.HttpsPort);

                        return new ContentResult
                        {
                            Content = new Saml2MetadataGenerator(endpoints).GenerateMetadataDocument(),
                            ContentType = "text/xml"
                        };
                    });
                
            }
            return new HttpNotFoundResult();
        }
    }
}
