using System;
using System.Collections.Generic;
using System.Linq;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class UsersViewModel
    {
        private Repositories.IUserManagementRepository UserManagementRepository;

        public UsersViewModel(Repositories.IUserManagementRepository UserManagementRepository, string filter)
        {
            this.UserManagementRepository = UserManagementRepository;
            this.Filter = filter;

            if (String.IsNullOrEmpty(filter))
            {
                Users = UserManagementRepository.GetUsers();
                Total = Showing = Users.Count();
            }
            else
            {
                Users = UserManagementRepository.GetUsers(filter);
                Total = UserManagementRepository.GetUsers().Count();
                Showing = Users.Count();
            }

            UsersDeleteList = Users.Select(x => new UserDeleteModel { Username = x }).ToArray();
        }

        public IEnumerable<string> Users { get; set; }
        public UserDeleteModel[] UsersDeleteList {get;set;}
        public string Filter { get; set; }
        public int Total { get; set; }
        public int Showing { get; set; }
    }

    public class UserDeleteModel
    {
        public string Username { get; set; }
        public bool Delete { get; set; }
    }
}