﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.18449
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Thinktecture.IdentityServer.Resources.Models {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    public class IdentityProvider {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal IdentityProvider() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Thinktecture.IdentityServer.Resources.Models.IdentityProvider", typeof(IdentityProvider).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Client ID.
        /// </summary>
        public static string ClientID {
            get {
                return ResourceManager.GetString("ClientID", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Client ID is required..
        /// </summary>
        public static string ClientIDRequiredError {
            get {
                return ResourceManager.GetString("ClientIDRequiredError", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Client Secret.
        /// </summary>
        public static string ClientSecret {
            get {
                return ResourceManager.GetString("ClientSecret", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Client Secret is required..
        /// </summary>
        public static string ClientSecretRequiredError {
            get {
                return ResourceManager.GetString("ClientSecretRequiredError", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Display Name.
        /// </summary>
        public static string DisplayName {
            get {
                return ResourceManager.GetString("DisplayName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Descriptive Name of the identity provider (for logging)..
        /// </summary>
        public static string DisplayNameDescription {
            get {
                return ResourceManager.GetString("DisplayNameDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Enabled.
        /// </summary>
        public static string Enabled {
            get {
                return ResourceManager.GetString("Enabled", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Specifies whether this provider will used..
        /// </summary>
        public static string EnabledDescription {
            get {
                return ResourceManager.GetString("EnabledDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Issuer Thumbprint.
        /// </summary>
        public static string IssuerThumbprint {
            get {
                return ResourceManager.GetString("IssuerThumbprint", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Specifies the issuer thumbprints for X.509 certificate based signature validation. One valid thumbprint per line..
        /// </summary>
        public static string IssuerThumbprintDescription {
            get {
                return ResourceManager.GetString("IssuerThumbprintDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Issuer Thumbprint is required..
        /// </summary>
        public static string IssuerThumbprintRequiredError {
            get {
                return ResourceManager.GetString("IssuerThumbprintRequiredError", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Identifier.
        /// </summary>
        public static string Name {
            get {
                return ResourceManager.GetString("Name", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unique identifier of the identity provider..
        /// </summary>
        public static string NameDescription {
            get {
                return ResourceManager.GetString("NameDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to OAuth2 Provider.
        /// </summary>
        public static string ProviderType {
            get {
                return ResourceManager.GetString("ProviderType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Profile Type is required..
        /// </summary>
        public static string ProviderTypeRequiredError {
            get {
                return ResourceManager.GetString("ProviderTypeRequiredError", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Include in Home Realm Discovery.
        /// </summary>
        public static string ShowInHrdSelection {
            get {
                return ResourceManager.GetString("ShowInHrdSelection", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Specifies whether this provider will be shown in the HRD screen..
        /// </summary>
        public static string ShowInHrdSelectionDescription {
            get {
                return ResourceManager.GetString("ShowInHrdSelectionDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Type.
        /// </summary>
        public static string Type {
            get {
                return ResourceManager.GetString("Type", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Specifies the type of the identity provider..
        /// </summary>
        public static string TypeDescription {
            get {
                return ResourceManager.GetString("TypeDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to WS-Federation Endpoint.
        /// </summary>
        public static string WSFederationEndpoint {
            get {
                return ResourceManager.GetString("WSFederationEndpoint", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Specifies the endpoint of for the WS-Federation protocol..
        /// </summary>
        public static string WSFederationEndpointDescription {
            get {
                return ResourceManager.GetString("WSFederationEndpointDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to WS-Federation Endpoint is required..
        /// </summary>
        public static string WSFederationEndpointRequiredError {
            get {
                return ResourceManager.GetString("WSFederationEndpointRequiredError", resourceCulture);
            }
        }
    }
}
