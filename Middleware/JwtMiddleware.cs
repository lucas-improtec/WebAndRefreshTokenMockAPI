using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using RefreshTokenAuth.Repositories;
using RefreshTokenAuth.Services;

namespace RefreshTokenAuth.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var username = TokenService.ValidateToken(token);
            if (username != null)
            {
                context.Items["User"] = UserRepository.Get(username, username);
            }

            await _next(context);
        }
    }
}