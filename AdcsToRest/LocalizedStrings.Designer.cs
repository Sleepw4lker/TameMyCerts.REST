﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace AdcsToRest {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "17.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class LocalizedStrings {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal LocalizedStrings() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("AdcsToRest.LocalizedStrings", typeof(LocalizedStrings).Assembly);
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
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to You do not have permission to request certificates from {0}..
        /// </summary>
        internal static string DESC_CA_DENIED {
            get {
                return ResourceManager.GetString("DESC_CA_DENIED", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to parse the given certificate request..
        /// </summary>
        internal static string DESC_INVALID_CSR {
            get {
                return ResourceManager.GetString("DESC_INVALID_CSR", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The certification authority {0} was not found..
        /// </summary>
        internal static string DESC_MISSING_CA {
            get {
                return ResourceManager.GetString("DESC_MISSING_CA", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The {0} parameter is missing or invalid..
        /// </summary>
        internal static string DESC_MISSING_PARAMETER {
            get {
                return ResourceManager.GetString("DESC_MISSING_PARAMETER", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The certificate template {0} was not found..
        /// </summary>
        internal static string DESC_MISSING_TEMPLATE {
            get {
                return ResourceManager.GetString("DESC_MISSING_TEMPLATE", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Unable to connect to certification authority because {0}..
        /// </summary>
        internal static string DESC_SUBMISSION_FAILED {
            get {
                return ResourceManager.GetString("DESC_SUBMISSION_FAILED", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to You do not have permission to enroll for {0}..
        /// </summary>
        internal static string DESC_TEMPLATED_DENIED {
            get {
                return ResourceManager.GetString("DESC_TEMPLATED_DENIED", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to unknown.
        /// </summary>
        internal static string UNKNOWN {
            get {
                return ResourceManager.GetString("UNKNOWN", resourceCulture);
            }
        }
    }
}
