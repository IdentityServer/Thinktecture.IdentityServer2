using System.ComponentModel.Composition;
using System.ComponentModel.DataAnnotations;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using System.Linq;
using System;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class OpenIdConnectClientInputModel : IValidatableObject
    {
        public OpenIdConnectClient Client { get; set; }

        public void MapRedirectUris()
        {
            this.RedirectUris = null;
            if (this.Client.RedirectUris != null && this.Client.RedirectUris.Any())
            {
                this.RedirectUris = this.Client.RedirectUris.Aggregate((x, y) => x + System.Environment.NewLine + y);
            }
        }
        
        [DataType(DataType.MultilineText)]
        [Display(Name = "Redirect Uris", Description = "List of URIs allowed to redirect to in OAuth2 protocol.")]
        public string RedirectUris { get; set; }
        
        public string[] ParsedRedirectUris
        {
            get
            {
                if (this.RedirectUris == null)
                {
                    return new string[0];
                }
                else
                {
                    return this.RedirectUris.Split(new string[] { System.Environment.NewLine }, System.StringSplitOptions.RemoveEmptyEntries);
                }
            }
        }

        public System.Collections.Generic.IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            foreach (var item in ParsedRedirectUris)
            {
                Uri val;
                if (!Uri.TryCreate(item, UriKind.Absolute, out val))
                {
                    yield return new ValidationResult(item + " is not a valid URI", new string[] { "RedirectUris" });
                }
            }
        }
    }

    public class OpenIdConnectClientViewModel : OpenIdConnectClientInputModel
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public OpenIdConnectClientViewModel(Models.OpenIdConnectClient client)
        {
            Container.Current.SatisfyImportsOnce(this);
            this.Client = client;
            this.MapRedirectUris();
        }

        public bool IsNew
        {
            get
            {
                return string.IsNullOrWhiteSpace(this.Client.ClientId);
            }
        }

        public bool IsOAuthRefreshTokenEnabled
        {
            get
            {
                return !IsNew && Client.Flow == OpenIdConnectFlows.AuthorizationCode;
            }
        }
    }
}