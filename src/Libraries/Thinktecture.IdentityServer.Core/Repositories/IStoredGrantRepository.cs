using Thinktecture.IdentityServer.Models;

namespace Thinktecture.IdentityServer.Repositories
{
    public interface IStoredGrantRepository
    {
        void Add(StoredGrant grant);
        StoredGrant Get(string id);
        void Delete(string id);
    }
}