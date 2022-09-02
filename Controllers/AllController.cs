using System;
using Microsoft.AspNetCore.Mvc;
using RefreshTokenAuth.Authorization;

namespace RefreshTokenAuth.Controllers
{
    [ApiController]
    public class AllController : ControllerBase
    {
        [HttpPost]
        [Route("all")]
        [Authorize]
        public string DefaultContent()
        {
            return "content: :)";
        }
    }
}
