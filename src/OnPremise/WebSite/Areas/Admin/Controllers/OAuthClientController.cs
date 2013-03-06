using System;
using System.ComponentModel.Composition;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.Controllers
{
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

            ModelState.AddModelError("", "Invalid Action");
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
                    TempData["Message"] = "Clients Deleted";
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", "Error deleting clients.");
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
                    TempData["Message"] = "Client Created";
                    return RedirectToAction("Edit", new { id = model.ID });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", "Error creating client.");
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
                    TempData["Message"] = "Client updated";
                    return RedirectToAction("Edit", new { id = model.ID });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", "Error creating client.");
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
                    TempData["Message"] = "Client Deleted";
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", "Error deleting client.");
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
