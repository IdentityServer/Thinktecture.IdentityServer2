using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class OAuthRefreshTokenIndexViewModel
    {
        public OAuthRefreshTokenIndexViewModel(
            TokenSearchCriteria searchCriteria,
            IClientsRepository clientRepository,
            ICodeTokenRepository codeTokenRepository,
            bool doSearch = false)
        {
            this.SearchCriteria = searchCriteria;
            var clients = 
                from item in clientRepository.GetAll()
                select new 
                {
                    item.Name, item.ID
                };
            var list =
                (from item in clients.ToArray()
                select new SelectListItem
                {
                    Text = item.Name, Value=item.ID.ToString()
                }).ToList();
            list.Insert(0, new SelectListItem { Text = Resources.OAuthRefreshTokenIndexViewModel.NoItemSelected, Value="" });
            this.Clients = list;

            if (searchCriteria.HasValues || doSearch)
            {
                var results = codeTokenRepository.Search(searchCriteria.ClientID, searchCriteria.Username, searchCriteria.Scope, CodeTokenType.RefreshTokenIdentifier);
                this.SearchResults = results.OrderBy(x=>x.TimeStamp);
            }
        }
        
        public TokenSearchCriteria SearchCriteria { get; private set; }
        public IEnumerable<SelectListItem> Clients { get; set; }
        public IEnumerable<CodeToken> SearchResults { get; set; }

        public string LookupClientId(int clientID)
        {
            return Clients.Where(x => x.Value == clientID.ToString()).Select(x => x.Text).SingleOrDefault();
        }
    }

    public class TokenSearchCriteria
    {
        [Display(ResourceType = typeof(Resources.TokenSearchCriteria), Name = "Username")]
        public string Username { get; set; }
        [Display(ResourceType = typeof(Resources.TokenSearchCriteria), Name = "Scope")]
        public string Scope { get; set; }
        [Display(ResourceType = typeof(Resources.TokenSearchCriteria), Name = "ClientId")]
        [ScaffoldColumn(false)]
        public int? ClientID { get; set; }
        [ScaffoldColumn(false)]
        public bool HasValues
        {
            get
            {
                return
                    !String.IsNullOrWhiteSpace(Username) ||
                    !String.IsNullOrWhiteSpace(Scope) ||
                    ClientID != null;
            }
        }
    }
}