/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Web.Mvc;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.ViewModels;

namespace Thinktecture.IdentityServer.Web.Controllers
{
    public class InitialConfigurationController : Controller
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IUserManagementRepository UserManagement { get; set; }

        public InitialConfigurationController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public InitialConfigurationController(IConfigurationRepository configuration, IUserManagementRepository userManagement)
        {
            ConfigurationRepository = configuration;
            UserManagement = userManagement;
        }

        public ActionResult Index()
        {
            if (ConfigurationRepository.Keys.SigningCertificate != null)
            {
                return RedirectToAction("index", "home");
            }

            var model = new InitialConfigurationModel
            {
                AvailableCertificates = GetAvailableCertificatesFromStore(),
                IssuerUri = ConfigurationRepository.Global.IssuerUri,
                SiteName = ConfigurationRepository.Global.SiteName
            };

            return View(model);
        }

        [HttpPost]
        public ActionResult Index(InitialConfigurationModel model)
        {
            if (ConfigurationRepository.Keys.SigningCertificate != null)
            {
                return RedirectToAction("index", "home");
            }

            if (ModelState.IsValid)
            {
                var config = ConfigurationRepository.Global;
                config.SiteName = model.SiteName;
                config.IssuerUri = model.IssuerUri;

                // create default IdentityServer groups and admin user.
                if (model.CreateDefaultAccounts)
                {
                    var errors = CreateDefaultAccounts(model.UserName, model.Password);

                    if (errors.Count != 0)
                    {
                        errors.ForEach(e => ModelState.AddModelError("", e));
                        model.AvailableCertificates = GetAvailableCertificatesFromStore();
                        return View(model);
                    }
                }

                // update global config
                ConfigurationRepository.Global = config;

                var keys = ConfigurationRepository.Keys;
                try
                {
                    var cert = X509.LocalMachine.My.SubjectDistinguishedName.Find(model.SigningCertificate, false).First();
                    
                    // make sure we can access the private key
                    var pk = cert.PrivateKey;
                    
                    keys.SigningCertificate = cert;
                }
                catch (CryptographicException)
                {
                    ModelState.AddModelError("", string.Format(Resources.InitialConfigurationController.NoReadAccessPrivateKey, WindowsIdentity.GetCurrent().Name));
                    model.AvailableCertificates = GetAvailableCertificatesFromStore();
                    return View(model);
                }

                if (string.IsNullOrWhiteSpace(keys.SymmetricSigningKey))
                {
                    keys.SymmetricSigningKey = Convert.ToBase64String(CryptoRandom.CreateRandomKey(32));
                }
                
                // updates key material config
                ConfigurationRepository.Keys = keys;


                
                return RedirectToAction("index", "home");
            }

            ModelState.AddModelError("", Resources.InitialConfigurationController.ErrorsOcurred);
            model.AvailableCertificates = GetAvailableCertificatesFromStore();
            return View(model);
        }

        private List<string> CreateDefaultAccounts(string userName, string password)
        {
            var errors = new List<string>();

            try
            {
                UserManagement.CreateRole(Constants.Roles.IdentityServerUsers);
            }
            catch (Exception ex)
            {
                errors.Add(ex.Message);
            }

            try
            {
                UserManagement.CreateRole(Constants.Roles.IdentityServerAdministrators);
            }
            catch (Exception ex)
            {
                errors.Add(ex.Message);
            }

            if (errors.Count != 0)
            {
                return errors;
            }


            try
            {
                UserManagement.CreateUser(userName, password);
            }
            catch (Exception ex)
            {
                errors.Add(ex.Message);
            }

            try
            {
                UserManagement.SetRolesForUser(userName, new string[] { Constants.Roles.IdentityServerAdministrators });
            }
            catch (Exception ex)
            {
                errors.Add(ex.Message);
            }

            return errors;
        }

        #region Helper
        private List<string> GetAvailableCertificatesFromStore()
        {
            var list = new List<string>();
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            try
            {
                foreach (var cert in store.Certificates)
                {
                    // todo: add friendly name
                    list.Add(string.Format("{0}", cert.Subject));
                }
            }
            finally
            {
                store.Close();
            }

            return list;
        }
        #endregion
    }
}
