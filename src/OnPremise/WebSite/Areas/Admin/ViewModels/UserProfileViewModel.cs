using System;
using System.Configuration;
using System.Linq;
using System.Web.Mvc;
using System.Web.Profile;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class UserProfileViewModel
    {
        public UserProfileViewModel(string username, ProfilePropertyInputModel[] values)
        {
            this.Username = username;
            this.ProfileValues = new ProfilePropertyViewModel[values.Length];

            for (int i = 0; i < this.ProfileValues.Length; i++)
            {
                var prop = ProfileBase.Properties[values[i].Name];
                this.ProfileValues[i] = new ProfilePropertyViewModel(prop, values[i]);
            }
        }

        public UserProfileViewModel(string username)
        {
            this.Username = username;

            if (ProfileBase.Properties != null && ProfileBase.Properties.Count > 0)
            {
                var propertyList = ProfileBase.Properties.Cast<SettingsProperty>().ToArray();
                var profile = ProfileBase.Create(username);
                var values =
                    from property in propertyList
                    where 
                        (property.PropertyType.IsValueType && !property.PropertyType.IsGenericType) || 
                        property.PropertyType == typeof(string)
                    select new ProfilePropertyViewModel(property, Convert.ToString(profile[property.Name]));
                ProfileValues = values.ToArray();
            }
        }

        public bool UpdateProfileFromValues(ModelStateDictionary errors)
        {
            if (ProfileValues.All(x => String.IsNullOrWhiteSpace(x.Data.Value)))
            {
                ProfileManager.DeleteProfile(Username);
                return true;
            }

            var profile = ProfileBase.Create(Username);
            for (int i = 0; i < ProfileValues.Length; i++)
            {
                var prop = ProfileBase.Properties[ProfileValues[i].Data.Name];
                try
                {
                    if (String.IsNullOrWhiteSpace(ProfileValues[i].Data.Value) && 
                        prop.PropertyType.IsValueType)
                    {
                        errors.AddModelError("profileValues[" + i + "].value", string.Format(Resources.UserProfileViewModel.RequiredProperty, prop.Name));
                    }
                    else
                    {
                        object val = Convert.ChangeType(ProfileValues[i].Data.Value, prop.PropertyType);
                        profile.SetPropertyValue(prop.Name, val);
                    }
                }
                catch (FormatException ex)
                {
                    errors.AddModelError("profileValues[" + i + "].value", string.Format(Resources.UserProfileViewModel.ErrorConvertingPropertyValueEx, prop.Name, ex.Message));
                }
                catch (Exception)
                {
                    errors.AddModelError("profileValues[" + i + "].value", string.Format(Resources.UserProfileViewModel.ErrorConvertingPropertyValueType, prop.Name, prop.PropertyType.Name));
                }
            }

            if (errors.IsValid)
            {
                try
                {
                    profile.Save();
                }
                catch (Exception ex)
                {
                    errors.AddModelError("", Resources.UserProfileViewModel.ErrorUpdatingProfile);
                    Tracing.Error(ex.Message);
                }
            }

            return errors.IsValid;
        }

        public string Username { get; set; }
        public ProfilePropertyViewModel[] ProfileValues { get; set; }
    }

    public class ProfilePropertyViewModel
    {
        public ProfilePropertyViewModel(SettingsProperty property, ProfilePropertyInputModel value)
        {
            Type = PropTypeFromPropertyType(property);
            Description = string.Format(property.PropertyType.IsValueType
                                            ? Resources.ProfilePropertyViewModel.RequiredPropertyMustBeOfType
                                            : Resources.ProfilePropertyViewModel.RequiredProperty,
                                        property.Name, property.PropertyType.Name);

            Data = value;
        }

        public ProfilePropertyViewModel(SettingsProperty property, string value)
            : this(property, 
                    new ProfilePropertyInputModel
                    {
                        Name = property.Name,
                        Value = value
                    })
        {
        }
        
        ProfilePropertyViewModel.ProfilePropertyType PropTypeFromPropertyType(SettingsProperty prop)
        {
            return prop.PropertyType == typeof(Boolean) ?
                    ProfilePropertyViewModel.ProfilePropertyType.Boolean :
                    ProfilePropertyViewModel.ProfilePropertyType.String;
        }

        public enum ProfilePropertyType
        {
            String,
            Boolean
        }

        public ProfilePropertyType Type { get; set; }
        public string Description { get; set; }
        public ProfilePropertyInputModel Data { get; set; }
    }

    public class ProfilePropertyInputModel
    {
        public string Name { get; set; }
        public string Value { get; set; }
    }
}