/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Linq;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    public class OpenIdConnectClientsRepository : IOpenIdConnectClientsRepository
    {
        public bool ValidateClient(string clientId, string clientSecret)
        {
            Models.OpenIdConnectClient client;
            return ValidateClient(clientId, clientSecret, out client);

        }

        public bool ValidateClient(string clientId, string clientSecret, out Models.OpenIdConnectClient client)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var record = entities.OpenIdConnectClients.Find(clientId);
                if (record != null)
                {
                    if (Thinktecture.IdentityServer.Helper.CryptoHelper.VerifyHashedPassword(record.ClientSecret, clientSecret))
                    {
                        client = record.ToDomainModel();
                        return true;
                    }
                }
                
                client = null;
                return false;
            }
        }

        public IEnumerable<Models.OpenIdConnectClient> GetAll()
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                return entities.OpenIdConnectClients.ToArray().Select(x => x.ToDomainModel()).ToArray();
            }
        }

        public Models.OpenIdConnectClient Get(string clientId)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = entities.OpenIdConnectClients.Include("RedirectUris").Where(x=>x.ClientId==clientId).SingleOrDefault();
                if (item != null) return item.ToDomainModel();
            }

            return null;
        }

        public void Delete(string clientId)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = entities.OpenIdConnectClients.Find(clientId);
                if (item != null)
                {
                    entities.OpenIdConnectClients.Remove(item);
                    entities.SaveChanges();
                }
            }
        }

        public void Update(Models.OpenIdConnectClient model)
        {
            if (model == null) throw new ArgumentNullException("model");
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = entities.OpenIdConnectClients.Find(model.ClientId);
                if (item != null)
                {
                    model.UpdateEntity(item);
                    entities.SaveChanges();
                }
            }
        }

        public void Create(Models.OpenIdConnectClient model)
        {
            if (model == null) throw new ArgumentNullException("model");
            var item = new OpenIdConnectClientEntity();
            model.UpdateEntity(item);
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                entities.OpenIdConnectClients.Add(item);
                entities.SaveChanges();
            }
        }
    }
}
