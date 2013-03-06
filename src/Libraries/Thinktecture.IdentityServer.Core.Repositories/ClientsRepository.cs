/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Linq;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    /// <summary>
    /// TODO: Update summary.
    /// </summary>
    public class ClientsRepository : IClientsRepository
    {
        public bool ValidateClient(string clientId, string clientSecret)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var client = (from c in entities.Clients
                              where c.ClientId.Equals(clientId, StringComparison.Ordinal) &&
                                    c.ClientSecret.Equals(clientSecret, StringComparison.Ordinal)
                              select c).SingleOrDefault();

                return (client != null);
            }
            
        }

        public bool TryGetClient(string clientId, out Models.Client client)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var record = (from c in entities.Clients
                              where c.ClientId.Equals(clientId, StringComparison.Ordinal)
                              select c).SingleOrDefault();

                if (record != null)
                {
                    client = record.ToDomainModel();
                    return true;
                }

                client = null;
                return false;
            }
        }

        public bool ValidateAndGetClient(string clientId, string clientSecret, out Models.Client client)
        {
            if (TryGetClient(clientId, out client))
            {
                if (client.ClientSecret.Equals(clientSecret, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            client = null;
            return false;
        }
        
        public IEnumerable<Models.Client> GetAll()
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                return entities.Clients.ToArray().Select(x => x.ToDomainModel()).ToArray();
            }
        }


        public void Delete(int id)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = entities.Clients.Where(x => x.Id == id).SingleOrDefault();
                if (item != null)
                {
                    entities.Clients.Remove(item);
                    entities.SaveChanges();
                }
            }
        }
        public void Update(Models.Client model)
        {
            if (model == null) throw new ArgumentException("model");

            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = entities.Clients.Where(x => x.Id == model.ID).Single();
                model.UpdateEntity(item);
                entities.SaveChanges();
            }
        }

        public void Create(Models.Client model)
        {
            if (model == null) throw new ArgumentException("model");

            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = new Client();
                model.UpdateEntity(item);
                entities.Clients.Add(item);
                entities.SaveChanges();
                model.ID = item.Id;
            }
        }


        public Models.Client Get(int id)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = entities.Clients.Where(x => x.Id == id).SingleOrDefault();
                if (item != null)
                {
                    return item.ToDomainModel();
                }
                return null;
            }
        }
    }
}
