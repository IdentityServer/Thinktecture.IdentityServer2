using System.Collections.Generic;
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
    public class RPController : Controller
    {
        [Import]
        public IRelyingPartyRepository RelyingPartyRepository { get; set; }

        public RPController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public RPController(IRelyingPartyRepository relyingPartyRepository)
        {
            this.RelyingPartyRepository = relyingPartyRepository;
        }

        public ActionResult Index()
        {
            var vm = new RelyingPartiesViewModel(RelyingPartyRepository);
            return View("Index", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string action, IEnumerable<RelyingPartyViewModel> list)
        {
            if (action == "save")
            {
                var vm = new RelyingPartiesViewModel(RelyingPartyRepository);
                if (ModelState.IsValid)
                {
                    vm.Update(list);
                    TempData["Message"] = Resources.RPController.UpdateSuccessful;
                    return RedirectToAction("Index");
                }

                return View("Index", vm);
            }

            if (action == "new")
            {
                return RedirectToAction("RP");
            }

            ModelState.AddModelError("", Resources.RPController.InvalidAction);
            return View("Index", new RelyingPartiesViewModel(RelyingPartyRepository));
        }

        [ChildActionOnly]
        public ActionResult Menu()
        {
            var rpvm = new RelyingPartiesViewModel(RelyingPartyRepository);
            var list = rpvm.RPs.Where(x => x.Enabled);
            if (list.Any())
            {
                var vm = new ChildMenuViewModel
                {
                    Items = list.Select(x=>
                        new ChildMenuItem
                        {
                            Controller = "RP",
                            Action = "RP",
                            Title = x.DisplayName,
                            RouteValues = new{id=x.ID}
                        }).ToArray()
                };
                return PartialView("ChildMenu", vm);
            }
            return new EmptyResult();
        }

        public ActionResult RP(string id)
        {
            RelyingParty rp = null;
            if (id == null) rp = new RelyingParty();
            else rp = this.RelyingPartyRepository.Get(id);
            if (rp == null) return HttpNotFound();
            return View("RP", rp);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult RP(string id,
            string action,
            [Bind(Exclude = "EncryptingCertificate")] RelyingParty rp,
            RPCertInputModel cert)
        {
            if (action == "create")
            {
                return CreateRP(rp, cert);
            }
            if (action == "save")
            {
                return SaveRP(id, rp, cert);
            }
            if (action == "delete")
            {
                return DeleteRP(id);
            }

            var origRP = this.RelyingPartyRepository.Get(id);
            rp.EncryptingCertificate = origRP.EncryptingCertificate;

            ModelState.AddModelError("", Resources.RPController.InvalidAction);
            return View("RP", rp);
        }

        private ActionResult DeleteRP(string id)
        {
            try
            {
                this.RelyingPartyRepository.Delete(id);
                TempData["Message"] = Resources.RPController.DeleteSuccessful;
                return RedirectToAction("Index");
            }
            catch (ValidationException ex)
            {
                ModelState.AddModelError("", ex.Message);
            }
            catch
            {
                ModelState.AddModelError("", Resources.RPController.ErrorDeletingRelyingParty);

            }

            var rp = this.RelyingPartyRepository.Get(id);
            return View("RP", rp);
        }

        private ActionResult CreateRP(RelyingParty rp, RPCertInputModel cert)
        {
            // ID is not required for create
            ModelState["ID"].Errors.Clear();

            rp.Id = null;
            rp.EncryptingCertificate = cert.Cert;

            if (ModelState.IsValid)
            {
                try
                {
                    this.RelyingPartyRepository.Add(rp);
                    TempData["Message"] = Resources.RPController.CreateSuccessful;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.RPController.ErrorCreatingRelyingParty);
                }
            }

            return View("RP", rp);
        }

        private ActionResult SaveRP(string id, RelyingParty rp, RPCertInputModel cert)
        {
            if (cert.RemoveCert == true)
            {
                rp.EncryptingCertificate = null;
            }
            else if (cert.Cert != null)
            {
                rp.EncryptingCertificate = cert.Cert;
            }
            else
            {
                var origRP = this.RelyingPartyRepository.Get(id);
                rp.EncryptingCertificate = origRP.EncryptingCertificate;
            }

            if (ModelState.IsValid)
            {
                try
                {
                    this.RelyingPartyRepository.Update(rp);
                    TempData["Message"] = Resources.RPController.UpdateSuccessful;
                    return RedirectToAction("RP", new { id });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.RPController.ErrorUpdatingRelyingParty);
                }
            }

            return View("RP", rp);
        }
    }
}


