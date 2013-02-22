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
    public class OAuthClientController : Controller
    {
        [Import]
        public IClientsRepository clientRepository { get; set; }

        public OAuthClientController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }
        public OAuthClientController(IClientsRepository clientRepository)
        {
            this.clientRepository = clientRepository;
        }

        public ActionResult Index()
        {
            var vm = new OAuthClientViewModel(this.clientRepository);
            return View("Index", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string action, OAuthClientInputModel[] list)
        {
            if (action == "new") return RedirectToAction("Edit");
            if (action == "delete") return Delete(list);

            ModelState.AddModelError("", Resources.OAuthClientController.InvalidAction);
            return Index();
        }

        private ActionResult Delete(OAuthClientInputModel[] list)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    foreach (var client in list.Where(x => x.Delete))
                    {
                        this.clientRepository.Delete(client.ID);
                    }
                    TempData["Message"] = Resources.OAuthClientController.ClientsDeleted;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OAuthClientController.ErrorDeletingClients);
                }
            }
            
            return Index();
        }

        public ActionResult Edit(int? id)
        {
            Client client = null;
            if (id != null && id > 0)
            {
                client = this.clientRepository.Get(id.Value);
                if (client == null) return HttpNotFound();
            }
            else
            {
                client = new Client();
            }
            
            return View("Edit", client);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(Client model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.clientRepository.Create(model);
                    TempData["Message"] = Resources.OAuthClientController.ClientCreated;
                    return RedirectToAction("Edit", new { id = model.ID });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OAuthClientController.ErrorCreatingClient);
                }
            }

            return Edit(model.ID);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Update(Client model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.clientRepository.Update(model);
                    TempData["Message"] = Resources.OAuthClientController.ClientUpdated;
                    return RedirectToAction("Edit", new { id = model.ID });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OAuthClientController.ErrorUpdatingClient);
                }
            }

            return Edit(model.ID);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.clientRepository.Delete(id);
                    TempData["Message"] = Resources.OAuthClientController.ClientDeleted;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.OAuthClientController.ErrorDeletingClient);
                }
            }

            return Edit(id);
        }

        [ChildActionOnly]
        public ActionResult Menu()
        {
            var list = new OAuthClientViewModel(this.clientRepository);
            if (list.Clients.Any())
            {
                var vm = new ChildMenuViewModel
                {
                    Items = list.Clients.Select(x =>
                        new ChildMenuItem
                        {
                            Controller = "OAuthClient",
                            Action = "Edit",
                            Title = x.Name,
                            RouteValues = new { id = x.ID }
                        }).ToArray()
                };
                return PartialView("ChildMenu", vm);
            }
            return new EmptyResult();
        }


    }
}
