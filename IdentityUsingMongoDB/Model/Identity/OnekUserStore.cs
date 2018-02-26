using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityUsingMongoDB.Model.Identity
{
    public class OnekUserStore : IUserStore<OnekUser>,
                         IUserClaimStore<OnekUser>,
                         IUserLoginStore<OnekUser>,
                         IUserRoleStore<OnekUser>,
                         IUserPasswordStore<OnekUser>,
                         IUserSecurityStampStore<OnekUser>
    {

        static List<OnekUser> users = new List<OnekUser>();
        public OnekUserStore()
        {

        }

        public int MyProperty { get; set; }
        public Task AddClaimsAsync(OnekUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task AddLoginAsync(OnekUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task AddToRoleAsync(OnekUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> CreateAsync(OnekUser user, CancellationToken cancellationToken)
        {
            return Task.Run(() => { users.Add(user); return IdentityResult.Success; });
        }

        public Task<IdentityResult> DeleteAsync(OnekUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            //throw new NotImplementedException();
        }

        public Task<OnekUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<OnekUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<OnekUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            return Task.Run(() => users.Where(e => e.NormalizedUserName == normalizedUserName).FirstOrDefault());
        }

        public Task<IList<Claim>> GetClaimsAsync(OnekUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(OnekUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetNormalizedUserNameAsync(OnekUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetPasswordHashAsync(OnekUser user, CancellationToken cancellationToken)
        {
            return Task.Run(() => user.PasswordHash);
        }

        public Task<IList<string>> GetRolesAsync(OnekUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetSecurityStampAsync(OnekUser user, CancellationToken cancellationToken)
        {
            return Task.Run(() => DateTime.UtcNow.ToLongDateString());
        }

        public Task<string> GetUserIdAsync(OnekUser user, CancellationToken cancellationToken)
        {
            return Task.Run(() => user.Id);
        }

        public Task<string> GetUserNameAsync(OnekUser user, CancellationToken cancellationToken)
        {
            return Task.Run(() => user.Email);
        }

        public Task<IList<OnekUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IList<OnekUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> HasPasswordAsync(OnekUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> IsInRoleAsync(OnekUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveClaimsAsync(OnekUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveFromRoleAsync(OnekUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveLoginAsync(OnekUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task ReplaceClaimAsync(OnekUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetNormalizedUserNameAsync(OnekUser user, string normalizedName, CancellationToken cancellationToken)
        {
            return Task.Run(() => user.NormalizedUserName = normalizedName);
        }

        public Task SetPasswordHashAsync(OnekUser user, string passwordHash, CancellationToken cancellationToken)
        {

            return Task.Run(() => user.PasswordHash = passwordHash);
        }

        public Task SetSecurityStampAsync(OnekUser user, string stamp, CancellationToken cancellationToken)
        {
            return Task.Run(() => user.SecurityStamp = stamp);
        }

        public Task SetUserNameAsync(OnekUser user, string userName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> UpdateAsync(OnekUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
