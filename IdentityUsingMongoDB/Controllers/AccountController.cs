using IdentityUsingMongoDB;
using IdentityUsingMongoDB.Model.Identity;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;


namespace IdentityUsingMongoDB.Controllers
{
    [Route("api/[Controller]")]
    public class AccountController : Controller
    {
        private readonly SignInManager<OnekUser> _signInManager;
        private readonly UserManager<OnekUser> _userManager;
        public AccountController(SignInManager<OnekUser> signInManager,
            UserManager<OnekUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }
        public IActionResult Get()
        {
            return Ok("TravelPlannerApp");
        }

        [Route("Register")]
        public async Task<IActionResult> Register(string username,string password)
        {
            var user = new OnekUser { UserName = username, Email = username };
            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
                return BadRequest("Something Went Wrong");
            return Ok();
        }

        [Route("Login")]
        public async Task<IActionResult> Login(string username, string password)
        {
            try { 
            var user = await _userManager.FindByNameAsync(username);

            if (user == null)
                return NotFound(username + " Isn't Found");
            var result = await _signInManager.CheckPasswordSignInAsync(user, password, true);

            var jwt = await GenerateJwT(user);
            return Ok(jwt);
            }
            catch (Exception e)
            {
                return BadRequest(e);
            }
        }
        [HttpPost]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("Private")]
        public async Task<IActionResult> Private()
        {
            return Ok("You are Authenticated");
        }

        private async Task<dynamic> GenerateJwT(OnekUser user)
        {
            //var roles = await _userManager.GetRolesAsync(user);

            var claims = new[]
           {
              new Claim(JwtRegisteredClaimNames.Sub, user.Email),
              new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
              new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName)
              //new Claim("roles",  string.Join(",",roles))
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Replace it in production for security"));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
              issuer: "1000ft",
              audience: "integrantUsers",
              claims: claims,
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: credentials);
          
            var x = new JwtSecurityTokenHandler().WriteToken(token);
            var results = new
            {
                token =x,
                expiration = token.ValidTo
            };
            return results;
        }
    }
}
