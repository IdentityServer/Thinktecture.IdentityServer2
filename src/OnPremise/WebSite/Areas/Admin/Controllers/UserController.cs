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
    public class UserController : Controller
    {
        [Import]
        public IUserManagementRepository UserManagementRepository { get; set; }

        public UserController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public UserController(IUserManagementRepository userManagementRepository)
        {
            UserManagementRepository = userManagementRepository;
        }

        public ActionResult Index(string filter = null)
        {
            var vm = new UsersViewModel(UserManagementRepository, filter);
            return View("Index", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(string action, UserDeleteModel[] list)
        {
            if (action == "new") return Create();
            if (action == "delete") return Delete(list);

            ModelState.AddModelError("", "Invalid action.");
            var vm = new UsersViewModel(UserManagementRepository, null);
            return View("Index", vm);

        }

        public ActionResult Create()
        {
            var rolesvm = new UserRolesViewModel(UserManagementRepository, String.Empty);
            var vm = new UserInputModel();
            vm.Roles = rolesvm.RoleAssignments;
            return View("Create", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(UserInputModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.UserManagementRepository.CreateUser(model.Username, model.Password, model.Email);
                    if (model.Roles != null)
                    {
                        var roles = model.Roles.Where(x => x.InRole).Select(x => x.Role);
                        if (roles.Any())
                        {
                            this.UserManagementRepository.SetRolesForUser(model.Username, roles);
                        }
                    }
                    TempData["Message"] = "User Created";
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", "Error creating user.");
                }
            }

            return View("Create", model);
        }

        private ActionResult Delete(UserDeleteModel[] list)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    foreach (var name in list.Where(x => x.Delete).Select(x => x.Username))
                    {
                        this.UserManagementRepository.DeleteUser(name);
                    }
                    TempData["Message"] = "Users Deleted";
                    return RedirectToAction("Index");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", "Error deleting user.");
                }
            }
            return Index();
        }

        public ActionResult Roles(string id)
        {
            var vm = new UserRolesViewModel(this.UserManagementRepository, id);
            return View("Roles", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Roles(string id, UserRoleAssignment[] roleAssignments)
        {
            var vm = new UserRolesViewModel(this.UserManagementRepository, id);
            if (ModelState.IsValid)
            {
                try
                {
                    var currentRoles =
                        roleAssignments.Where(x => x.InRole).Select(x => x.Role);
                    this.UserManagementRepository.SetRolesForUser(id, currentRoles);
                    TempData["Message"] = "Roles Assigned Successfully";
                    return RedirectToAction("Roles", new { id });
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
                catch
                {
                    ModelState.AddModelError("", "Error deleting user.");
                }
            }

            return View("Roles", vm);
        }
    }
}
