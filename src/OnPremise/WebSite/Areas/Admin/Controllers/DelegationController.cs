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
    public class DelegationController : Controller
    {
        [Import]
        public IUserManagementRepository userManagementRepository { get; set; }
        [Import]
        public IDelegationRepository delegationRepository { get; set; }

        public DelegationController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public DelegationController(IDelegationRepository delegationRepository, IUserManagementRepository userManagementRepository)
        {
            this.delegationRepository = delegationRepository;
            this.userManagementRepository = userManagementRepository;
        }

        public ActionResult Index()
        {
            var vm = new DelegationViewModel(this.delegationRepository);
            return View("Index", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string action, DelegationUser[] users)
        {
            if (action == "new") return Configure();
            if (action == "delete") return Delete(users);
            return RedirectToAction("Index");
        }

        private ActionResult Delete(DelegationUser[] users)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    foreach (var user in users.Where(x => x.Delete))
                    {
                        var settings = this.delegationRepository.GetDelegationSettingsForUser(user.Username);
                        foreach (var setting in settings)
                        {
                            this.delegationRepository.Delete(setting);
                        }
                    }
                    TempData["Message"] = Resources.DelegationController.DelegationUsersDeleted;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.DelegationController.ErrorDeletingDelegationUsers);
                }
            }

            return Index();
        }

        public ActionResult Configure(string id = null)
        {
            var vm = new DelegationSettingsForUserViewModel(this.delegationRepository, this.userManagementRepository, id);
            return View("Configure", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Add(DelegationSetting model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.delegationRepository.Add(model);
                    TempData["Message"] = Resources.DelegationController.RealmAdded;
                    return RedirectToAction("Configure", new { id = model.UserName });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.DelegationController.ErrorAddingDelegationSetting);
                }
            }

            var vm = new DelegationSettingsForUserViewModel(this.delegationRepository, this.userManagementRepository, model.UserName);
            return View("Configure", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Remove(DelegationSetting model)
        {
            try
            {
                this.delegationRepository.Delete(model);
                TempData["Message"] = Resources.DelegationController.RealmDeleted;
                return RedirectToAction("Configure", new { id = model.UserName });
            }
            catch (ValidationException ex)
            {
                ModelState.AddModelError("", ex.Message);
            }
            catch
            {
                ModelState.AddModelError("", Resources.DelegationController.ErrorDeletingDelegationSetting);
            }

            var vm = new DelegationSettingsForUserViewModel(this.delegationRepository, this.userManagementRepository, model.UserName);
            return View("Configure", vm);
        }
    }
}
