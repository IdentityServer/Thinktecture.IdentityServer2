using System;
using System.ComponentModel.Composition;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.Controllers
{
    [ClaimsAuthorize(Constants.Actions.Administration, Constants.Resources.Configuration)]
    public class ProtocolController : Controller
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public ProtocolController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public ProtocolController(IConfigurationRepository configurationRepository)
        {
            ConfigurationRepository = configurationRepository;
        }

        public ActionResult Index()
        {
            var vm = new ProtocolsViewModel(ConfigurationRepository);
            return View("Index", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(ProtocolsInputModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    model.Update(this.ConfigurationRepository);
                    TempData["Message"] = Resources.ProtocolController.UpdateSuccessful;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.ProtocolController.ErrorUpdatingProtocols);
                }
            }

            var vm = new ProtocolsViewModel(ConfigurationRepository);
            return View("Index", vm);
        }

        [ChildActionOnly]
        public ActionResult Menu()
        {
            var pvm = new ProtocolsViewModel(ConfigurationRepository);
            var list = pvm.Protocols.Where(x => x.Enabled).ToArray();
            if (list.Length > 0)
            {
                var vm = new ChildMenuViewModel();
                vm.Items = list.Select(x =>
                    new ChildMenuItem
                    {
                        Controller = "Protocol",
                        Action = "Protocol",
                        Title = x.Name,
                        RouteValues = new { id = x.NameWithoutSpaces }
                    }).ToArray();
                return PartialView("ChildMenu", vm);
            }
            return new EmptyResult();
        }

        public ActionResult Protocol(string id)
        {
            var vm = new ProtocolsViewModel(this.ConfigurationRepository);
            var protocol = vm.GetProtocol(id);
            if (protocol == null) return HttpNotFound();
            return View("Protocol", protocol);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult UpdateProtocol(string id)
        {
            var vm = new ProtocolsViewModel(this.ConfigurationRepository);
            var protocol = vm.GetProtocol(id);
            if (this.TryUpdateModel(protocol.Protocol, "protocol"))
            {
                try
                {
                    vm.UpdateProtocol(protocol);
                    TempData["Message"] = Resources.ProtocolController.UpdateSuccessful;
                    return RedirectToAction("Protocol", new { id });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.ProtocolController.ErrorUpdatingProtocol);
                }
            }
            return View("Protocol", protocol);
        }

        bool TryUpdateModel(object model, string prefix)
        {
            if (model == null)
            {
                throw new ArgumentNullException("model");
            }
            var valueProvider = this.ValueProvider;

            Predicate<string> predicate = delegate(string propertyName)
            {
                return IsPropertyAllowed(propertyName, null, null);
            };
            var modelType = model.GetType();
            IModelBinder binder = this.Binders.GetBinder(modelType);
            ModelBindingContext context2 = new ModelBindingContext();
            context2.ModelMetadata = ModelMetadataProviders.Current.GetMetadataForType(delegate
            {
                return model;
            }, modelType);
            context2.ModelName = prefix;
            context2.ModelState = this.ModelState;
            context2.PropertyFilter = predicate;
            context2.ValueProvider = valueProvider;
            ModelBindingContext bindingContext = context2;
            binder.BindModel(base.ControllerContext, bindingContext);
            return this.ModelState.IsValid;
        }

        internal static bool IsPropertyAllowed(string propertyName, string[] includeProperties, string[] excludeProperties)
        {
            bool flag = ((includeProperties == null) || (includeProperties.Length == 0)) || includeProperties.Contains<string>(propertyName, StringComparer.OrdinalIgnoreCase);
            bool flag2 = (excludeProperties != null) && excludeProperties.Contains<string>(propertyName, StringComparer.OrdinalIgnoreCase);
            return (flag && !flag2);
        }
    }
}
