using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthenticationService.Core.Services.Interfaces;
using AuthenticationService.Dal.Models;
using GenericDal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using BC = BCrypt.Net.BCrypt;

namespace AuthenticationService.Core.Services
{
    public class AuthenticationService: IAuthenticationService
    {
        private readonly ILogger<AuthenticationService> _logger;
        private readonly IAsyncRepository<Account, long> _accountRepository;
        private readonly SigningCredentials _signingCredentials;
        private readonly JwtSecurityTokenHandler _tokenHandler;

        public AuthenticationService(
            ILogger<AuthenticationService> logger, 
            IAsyncRepository<Account, long> accountRepository,
            IConfiguration configuration)
        {
            _logger = logger;
            _accountRepository = accountRepository;
            _signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(
                        configuration.GetSection("AppSettings")["Secret"])),
                SecurityAlgorithms.HmacSha256Signature);
            _tokenHandler = new JwtSecurityTokenHandler();
        }

        public async Task<string> Login(string email, string password)
        {
            Account account = await _accountRepository.FirstOrDefaultAsync(a => a.Email == email);
            
            // check account found and verify password
            if (account == null || !BC.Verify(password, account.Password))
            {
                // authentication failed
                //throw new FailedLoginAttemptException();
            }
            
            // authentication successful
            SecurityTokenDescriptor tokenDescriptor = new ()
            {
                SigningCredentials = _signingCredentials,
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("id", account.Id.ToString()),
                    new Claim(ClaimTypes.Email, account.Email)
                }),
                Expires = DateTime.Now.AddDays(7)
            };
            return _tokenHandler.WriteToken(_tokenHandler.CreateToken(tokenDescriptor));
        }

        public Task<bool> Register(string email, string password)
        {
            throw new System.NotImplementedException();
        }
    }
}