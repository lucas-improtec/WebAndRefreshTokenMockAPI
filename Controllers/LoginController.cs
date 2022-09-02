using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RefreshTokenAuth.Models;
using RefreshTokenAuth.Repositories;
using RefreshTokenAuth.Services;
using System.Threading.Tasks;

namespace RefreshTokenAuth.Controllers
{
    [ApiController]
    public class LoginController : ControllerBase
    {
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<dynamic>> Authenticate([FromBody] User model) 
        {
            var user = UserRepository.Get(model.Username, model.Password);

            if (user == null)
                return NotFound(new { message = "Usuário o senha inválidos" });

            var token = TokenService.GenerateToken(user);
            var refreshToken = TokenService.GenerateRefreshToken();
            TokenService.SaveRefreshToken(user.Username, refreshToken);

            user.Password = "";
            return new
            {
                user,
                token,
                refreshToken
            };
        }

        [HttpPost]
        [Route("refresh")]
        public IActionResult Refresh(string token, string refreshToken) 
        {
            // Adicionar validação aqui para ver se o token está expirado, se estiver descontinuar operação
            var principal = TokenService.GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name; // Para pegar qualquer informação (por exemplo: role) é só usa esse mesmo caminho
            var savedRefreshToken = TokenService.GetRefreshToken(username);
            if (savedRefreshToken != refreshToken)
                throw new SecurityTokenException("Invalid refresh token");

            var newJwtToken = TokenService.GenerateToken(principal.Claims);
            var newRefreshToken = TokenService.GenerateRefreshToken();
            TokenService.DeleteRefreshToken(username, refreshToken);
            TokenService.SaveRefreshToken(username, newRefreshToken);

            return new ObjectResult(new
            {
                token = newJwtToken,
                refreshToken = newRefreshToken
            });
        }
    }
}
