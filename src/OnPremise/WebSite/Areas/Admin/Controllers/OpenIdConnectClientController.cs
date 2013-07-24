using System;
using System.ComponentModel.Composition;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization.Mvc;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.Controllers
{
    [ClaimsAuthorize(Constants.Actions.Administration, Constants.Resources.Configuration)]
    public class OpenIdConnectClientController : Controller
    {
        [Import]
        public IOpenIdConnectClientsRepository repository { get; set; }

        public OpenIdConnectClientController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }
        public OpenIdConnectClientController(IOpenIdConnectClientsRepository repo)
        {
            this.repository = repo;
        }

        public ActionResult Index()
        {
            var vm = new OpenIdConnectClientIndexViewModel(this.repository);
            return View("Index", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string action, OpenIdConnectClientIndexInputModel[] list)
        {
            if (action == "new") return RedirectToAction("Edit");
            if (action == "delete") return Delete(list);

            ModelState.AddModelError("", Resources.OpenIdConnectClientController.InvalidAction);
            return Index();
        }

        private ActionResult Delete(OpenIdConnectClientIndexInputModel[] list)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    foreach (var client in list.Where(x => x.Delete))
                    {
                        this.repository.Delete(client.ClientId);
                    }
                    TempData["Message"] = Resources.OpenIdConnectClientController.ClientsDeleted;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OpenIdConnectClientController.ErrorDeletingClients);
                }
            }
            
            return Index();
        }

        public ActionResult Edit(string clientId)
        {
            OpenIdConnectClient client = null;
            if (!String.IsNullOrWhiteSpace(clientId))
            {
                client = this.repository.Get(clientId);
                if (client == null) return HttpNotFound();
            }
            else
            {
                client = new OpenIdConnectClient();
            }

            var vm = new OpenIdConnectClientViewModel(client); 
            return View("Edit", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(OpenIdConnectClientInputModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    model.Client.RedirectUris = model.ParsedRedirectUris;
                    this.repository.Create(model.Client);
                    TempData["Message"] = Resources.OpenIdConnectClientController.ClientCreated;
                    return RedirectToAction("Edit", new { clientId = model.Client.ClientId });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OpenIdConnectClientController.ErrorCreatingClient);
                }
            }

            return Edit(model.Client.ClientId);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Update(OpenIdConnectClientInputModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    model.Client.RedirectUris = model.ParsedRedirectUris;
                    this.repository.Update(model.Client);
                    TempData["Message"] = Resources.OpenIdConnectClientController.ClientUpdated;
                    return RedirectToAction("Edit", new { clientId = model.Client.ClientId });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OpenIdConnectClientController.ErrorUpdatingClient);
                }
            }

            return Edit(model.Client.ClientId);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(string clientId)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.repository.Delete(clientId);
                    TempData["Message"] = Resources.OpenIdConnectClientController.ClientDeleted;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OpenIdConnectClientController.ErrorDeletingClient);
                }
            }

            return Edit(clientId);
        }

        [ChildActionOnly]
        public ActionResult Menu()
        {
            var list = new OpenIdConnectClientIndexViewModel(this.repository);
            if (list.Clients.Any())
            {
                var vm = new ChildMenuViewModel
                {
                    Items = list.Clients.Select(x =>
                        new ChildMenuItem
                        {
                            Controller = "OpenIdConnectClient",
                            Action = "Edit",
                            Title = x.Name,
                            RouteValues = new { clientId = x.ClientId }
                        }).ToArray()
                };
                return PartialView("ChildMenu", vm);
            }
            return new EmptyResult();
        }


    }
}
