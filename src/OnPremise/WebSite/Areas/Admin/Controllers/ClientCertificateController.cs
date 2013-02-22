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
    public class ClientCertificateController : Controller
    {
        [Import]
        public IUserManagementRepository userManagementRepository { get; set; }
        [Import]
        public IClientCertificatesRepository clientCertificatesRepository { get; set; }

        public ClientCertificateController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }
        public ClientCertificateController(IClientCertificatesRepository clientCertificatesRepository, IUserManagementRepository userManagementRepository)
        {
            this.clientCertificatesRepository = clientCertificatesRepository;
            this.userManagementRepository = userManagementRepository;
        }

        public ActionResult Index()
        {
            var vm = new ClientCertificatesViewModel(this.clientCertificatesRepository);
            return View(vm);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string action, ClientCertificateUserInputModel[] users)
        {
            if (action == "new") return Configure();
            if (action == "delete") return Delete(users);
            return RedirectToAction("Index");
        }

        private ActionResult Delete(ClientCertificateUserInputModel[] users)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    foreach (var user in users.Where(x => x.Delete))
                    {
                        var settings = this.clientCertificatesRepository.GetClientCertificatesForUser(user.Username);
                        foreach (var setting in settings)
                        {
                            this.clientCertificatesRepository.Delete(setting);
                        }
                    }
                    TempData["Message"] = Resources.ClientCertificateController.UserCertificatesDeleted;
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", Resources.ClientCertificateController.ErrorDeletingClientCertificates);
                }
            }

            return Index();
        }

        public ActionResult Configure(string id = null)
        {
            var vm = new ClientCertificatesForUserViewModel(this.clientCertificatesRepository, this.userManagementRepository, id);
            return View("Configure", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Add(ClientCertificate newCertificate, ClientCertificateInputModel file)
        {
            if (String.IsNullOrEmpty(newCertificate.Thumbprint) && file != null && file.Cert != null)
            {
                newCertificate.Thumbprint = file.Cert.Thumbprint;
                if (newCertificate.Thumbprint != null)
                {
                    ModelState["newCertificate.Thumbprint"].Errors.Clear();
                    ModelState["newCertificate.Thumbprint"].Value = new ValueProviderResult(newCertificate.Thumbprint, newCertificate.Thumbprint, ModelState["newCertificate.Thumbprint"].Value.Culture);
                }
            }
            
            if (ModelState.IsValid)
            {
                try
                {
                    this.clientCertificatesRepository.Add(newCertificate);
                    TempData["Message"] = Resources.ClientCertificateController.CertificateAdded;
                    return RedirectToAction("Configure", new { id = newCertificate.UserName });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.ClientCertificateController.ErrorAddingClientCertificate);
                }
            }

            var vm = new ClientCertificatesForUserViewModel(this.clientCertificatesRepository, this.userManagementRepository, newCertificate.UserName);
            vm.NewCertificate = newCertificate;
            return View("Configure", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Remove(ClientCertificate model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.clientCertificatesRepository.Delete(model);
                    TempData["Message"] = Resources.ClientCertificateController.CertificateRemoved;
                    return RedirectToAction("Configure", new { id = model.UserName });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", Resources.ClientCertificateController.ErrorRemovingClientCertificate);
                }
            }

            var vm = new ClientCertificatesForUserViewModel(this.clientCertificatesRepository, this.userManagementRepository, model.UserName);
            return View("Configure", vm);
        }
    }
}
