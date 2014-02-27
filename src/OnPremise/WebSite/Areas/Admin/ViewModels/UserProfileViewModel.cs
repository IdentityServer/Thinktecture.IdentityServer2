using System;
using System.Configuration;
using System.Linq;
using System.Web.Mvc;
using System.Web.Profile;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class UserProfileViewModel
    {

        private readonly IClaimsRepository _claimsRepository;

        public UserProfileViewModel(IClaimsRepository claimsRepository, string username, ProfilePropertyInputModel[] values)
        {
            _claimsRepository = claimsRepository;

            Username = username;
            
            ProfileValues = new ProfilePropertyViewModel[values.Length];
            
            var profileProperties =
                _claimsRepository.GetProfileProperties(username).ToDictionary(property => property.Name);

            for (int i = 0; i < ProfileValues.Length; i++)
            {
                var prop = profileProperties[values[i].Name];
                ProfileValues[i] = new ProfilePropertyViewModel(prop.Name, values[i].Value, prop.PropertyType);
            }
        }

        public UserProfileViewModel(IClaimsRepository claimsRepository, string username)
        {
            _claimsRepository = claimsRepository;

            Username = username;

            if(claimsRepository.GetProfileProperties(username).Any())
            {
                var profileProperties = claimsRepository.GetProfileProperties(username).ToArray();
                var values =
                    from property in profileProperties
                    select new ProfilePropertyViewModel(property.Name, Convert.ToString(property.Value), property.PropertyType);
                ProfileValues = values.ToArray();
            }
        }

        public bool UpdateProfileFromValues(ModelStateDictionary errors)
        {
            var profileProperties =
                _claimsRepository.GetProfileProperties().ToDictionary(property => property.Name);

            for (int i = 0; i < ProfileValues.Length; i++)
            {
                var prop = profileProperties[ProfileValues[i].Data.Name];
                try
                {
                    if (String.IsNullOrWhiteSpace(ProfileValues[i].Data.Value) &&
                        prop.PropertyType.IsValueType)
                    {
                        errors.AddModelError("profileValues[" + i + "].value", string.Format(Resources.UserProfileViewModel.RequiredProperty, prop.Name));
                    }
                    else
                    {
                        profileProperties[prop.Name].Value = Convert.ChangeType(ProfileValues[i].Data.Value, prop.PropertyType);
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
                    _claimsRepository.UpdateProfileProperties(Username, profileProperties.Values.ToArray());
                }
                catch (Exception ex)
                {
                    errors.AddModelError("", "Error updating profile.");
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

        public ProfilePropertyViewModel(string name, string value, Type type)
        {
            Type = PropTypeFromPropertyType(type);
            
            Description = string.Format(type.IsValueType
                                            ? Resources.ProfilePropertyViewModel.RequiredPropertyMustBeOfType
                                            : Resources.ProfilePropertyViewModel.RequiredProperty,
                                        name, type.Name);

            Data = new ProfilePropertyInputModel
            {
                Name = name,
                Value = value
            };
        }

        ProfilePropertyType PropTypeFromPropertyType(SettingsProperty prop)
        {
            return PropTypeFromPropertyType(prop.PropertyType);
        }

        ProfilePropertyType PropTypeFromPropertyType(Type type)
        {
            return type == typeof(Boolean) ?
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