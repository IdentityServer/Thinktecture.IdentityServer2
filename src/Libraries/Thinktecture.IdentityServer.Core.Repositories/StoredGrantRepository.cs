using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityModel;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    public class StoredGrantRepository : IStoredGrantRepository
    {
        public void Add(Models.StoredGrant grant)
        {
            var entity = grant.ToEntityModel();

            using (var entities = IdentityServerConfigurationContext.Get())
            {
                entities.StoredGrants.Add(entity);
                entities.SaveChanges();
            }
        }

        public Models.StoredGrant Get(string id)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var result = (from sg in entities.StoredGrants
                              where sg.GrantId == id
                              select sg)
                             .SingleOrDefault();

                if (result != null)
                {
                    return result.ToDomainModel();
                }

                return null;
            }
        }

        public void Delete(string id)
        {
            using (var entities = IdentityServerConfigurationContext.Get())
            {
                var item = entities.StoredGrants.Where(x => x.GrantId.Equals(id, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                if (item != null)
                {
                    entities.StoredGrants.Remove(item);
                    entities.SaveChanges();
                }
            }
        }
    }
}
