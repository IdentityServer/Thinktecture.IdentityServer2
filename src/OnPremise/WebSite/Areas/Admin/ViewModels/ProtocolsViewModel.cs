using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Thinktecture.IdentityServer.Models.Configuration;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web.Areas.Admin.ViewModels
{
    public class ProtocolsViewModel
    {
        static List<Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>> protocolMap =
            new List<Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>>();
        static ProtocolsViewModel()
        {
            protocolMap.Add(new Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>(
                "WS-Federation",
                x => x.WSFederation,
                (c, v) => { c.WSFederation = (WSFederationConfiguration)v; }));
            protocolMap.Add(new Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>(
                "Federation Metadata",
                x => x.FederationMetadata,
                (c, v) => { c.FederationMetadata = (FederationMetadataConfiguration)v; }));
            protocolMap.Add(new Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>(
                "WS-Trust",
                x => x.WSTrust,
                (c, v) => { c.WSTrust = (WSTrustConfiguration)v; }));
            protocolMap.Add(new Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>(
                "OpenID Connect",
                x => x.OpenIdConnect,
                (c, v) => { c.OpenIdConnect = (OpenIdConnectConfiguration)v; }));
            protocolMap.Add(new Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>(
                "OAuth2",
                x => x.OAuth2,
                (c, v) => { c.OAuth2 = (OAuth2Configuration)v; }));
            protocolMap.Add(new Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>(
                "ADFS Integration",
                x => x.AdfsIntegration,
                (c, v) => { c.AdfsIntegration = (AdfsIntegrationConfiguration)v; }));
            protocolMap.Add(new Tuple<string, Func<IConfigurationRepository, ProtocolConfiguration>, Action<IConfigurationRepository, ProtocolConfiguration>>(
                "Simple HTTP",
                x => x.SimpleHttp,
                (c, v) => { c.SimpleHttp = (SimpleHttpConfiguration)v; }));
        }

        private Repositories.IConfigurationRepository ConfigurationRepository;

        public ProtocolsViewModel(Repositories.IConfigurationRepository ConfigurationRepository)
        {
            this.ConfigurationRepository = ConfigurationRepository;
            
            for (int i = 0; i < protocolMap.Count; i++)
            {
                var item = protocolMap[i];
                var id = i;
                var name = item.Item1;
                var enabled = item.Item2(this.ConfigurationRepository).Enabled;
                protocols.Add(new Protocol { ID = id, Name = name, Enabled = enabled });
            }
        }

        public class Protocol
        {
            public int ID { get; set; }
            public string Name { get; set; }
            public bool Enabled { get; set; }
            public string NameWithoutSpaces
            {
                get { return this.Name.Replace(" ", ""); }
            }
        }

        List<Protocol> protocols = new List<Protocol>();
        public IEnumerable<Protocol> Protocols
        {
            get
            {
                return protocols;
            }
        }

        internal void Update(bool[] values)
        {
            for (int i = 0; i < values.Length; i++)
            {
                var protocol = protocolMap[i].Item2(this.ConfigurationRepository);
                protocol.Enabled = values[i];
                protocolMap[i].Item3(ConfigurationRepository, protocol);
            }
        }

        internal ProtocolViewModel GetProtocol(string id)
        {
            var p = this.protocols.Where(x => x.NameWithoutSpaces == id).SingleOrDefault();
            if (p != null)
            {
                return new ProtocolViewModel
                {
                    DisplayName = p.Name,
                    ID = p.NameWithoutSpaces,
                    Protocol = protocolMap[p.ID].Item2(this.ConfigurationRepository)
                };
            }

            return null;
        }

        internal void UpdateProtocol(ProtocolViewModel protocol)
        {
            var p = this.protocols.Where(x => x.NameWithoutSpaces == protocol.ID).SingleOrDefault();
            if (p != null)
            {
                var mapping = protocolMap[p.ID];
                mapping.Item3(this.ConfigurationRepository, protocol.Protocol);
            }
            else
            {
                throw new ValidationException(Resources.ProtocolsViewModel.InvalidProtocolIdentifier);
            }
        }
    }
}