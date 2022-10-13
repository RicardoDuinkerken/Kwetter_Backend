using System.Threading.Tasks;

namespace AuthenticationService.Core.Services.Interfaces
{
    public interface IAuthenticationService
    {
        Task<string> Login(string email, string password);
        Task<bool> Register(string email, string password);
    }
}