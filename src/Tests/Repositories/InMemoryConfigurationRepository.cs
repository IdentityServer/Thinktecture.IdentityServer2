/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using Thinktecture.IdentityServer.Models.Configuration;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Tests.Repositories
{
    class InMemoryConfigurationRepository : IConfigurationRepository
    {
        GlobalConfiguration _global;
        WSFederationConfiguration _wsfed;

        public DiagnosticsConfiguration Diagnostics
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Thinktecture.IdentityServer.Models.Configuration.FederationMetadataConfiguration FederationMetadata
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Thinktecture.IdentityServer.Models.Configuration.GlobalConfiguration Global
        {
            get
            {
                return _global;
            }
            set
            {
                _global = value;
            }
        }

        public Thinktecture.IdentityServer.Models.Configuration.KeyMaterialConfiguration Keys
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Thinktecture.IdentityServer.Models.Configuration.OAuth2Configuration OAuth2
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Thinktecture.IdentityServer.Models.Configuration.SimpleHttpConfiguration SimpleHttp
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public bool SupportsWriteAccess
        {
            get { throw new NotImplementedException(); }
        }

        public Thinktecture.IdentityServer.Models.Configuration.WSFederationConfiguration WSFederation
        {
            get
            {
                return _wsfed;
            }
            set
            {
                _wsfed = value;
            }
        }

        public Thinktecture.IdentityServer.Models.Configuration.WSTrustConfiguration WSTrust
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }


        public AdfsIntegrationConfiguration AdfsIntegration
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }


        public OpenIdConnectConfiguration OpenIdConnect
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }
    }
}
