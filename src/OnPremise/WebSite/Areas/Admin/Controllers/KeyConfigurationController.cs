using System.ComponentModel.Composition;
using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.Controllers
{
    [ClaimsAuthorize(Constants.Actions.Administration, Constants.Resources.Configuration)]
    public class KeyConfigurationController : Controller
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public KeyConfigurationController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public KeyConfigurationController(IConfigurationRepository configuration)
        {
            ConfigurationRepository = configuration;
        }

        public ActionResult Index()
        {
            var keys = this.ConfigurationRepository.Keys;
            var vm = new KeyConfigurationViewModel(keys);
            return View(vm);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(KeyConfigurationInputModel keys)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    keys.Update(this.ConfigurationRepository);
                    TempData["Message"] = Resources.KeyConfigurationController.UpdateSuccessful;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.KeyConfigurationController.ErrorUpdatingKeys);
                }
            }

            var vm = new KeyConfigurationViewModel(this.ConfigurationRepository.Keys);
            vm.Keys = keys;
            return View("Index", vm);
        }
    }
}
