using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IDriveApi.Authentication;
using IDriveApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace IDriveApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class IdentityController : ControllerBase
{

    private readonly UserManager<ApplicationUser> userManager;
    private readonly IConfiguration _configuration;

    public IdentityController(ILogger<IdentityController> logger, UserManager<ApplicationUser> userManager,
        IConfiguration configuration)
    {
        this.userManager = userManager;
        this._configuration = configuration;
    }
    
    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] User model)
    {
        var user = await userManager.FindByEmailAsync(model.Email);
        if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
        {
            var jwt = await GenerateJwt(model.Email);

            user.RefreshToken = GenerateRefreshToken();
            user.RefreshTokenExpiry = DateTime.UtcNow.AddHours(24);

            await userManager.UpdateAsync(user);
            
            return Ok(new
            {
                accessToken = jwt.Item1,
                expiration = jwt.Item2.ValidTo,
                username = user.UserName,
                firstName = user.FirstName,
                lastName = user.LastName,
                refreshToken = user.RefreshToken
            });
        }
        return Unauthorized();
    }
    
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] Refresh model)
    {
        var principal = GetPrincipalFromExpiredToken(model.AccessToken);

        if (principal?.Identity?.Name == null)
        {
            return Unauthorized();
        }

        var user = await userManager.FindByEmailAsync(principal.Identity.Name);

        if (user == null || user.RefreshToken != model.RefreshToken || user.RefreshTokenExpiry < DateTime.Now)
        {
            return Unauthorized();
        }

        var jwt = await GenerateJwt(principal.Identity.Name);
        
        return Ok(new
        {
            accessToken = jwt.Item1,
            expiration = jwt.Item2.ValidTo,
            username = user.UserName,
            firstName = user.FirstName,
            lastName = user.LastName,
            refreshToken = model.RefreshToken
        });
    }
    
    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] Registration registeringUser)
    {
        var user = await userManager.FindByEmailAsync(registeringUser.Email);

        if (user != null)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User already exists."});
        }
        
        ApplicationUser creatingUser = new ApplicationUser()
        {
            UserName = registeringUser.FirstName + "_" + registeringUser.LastName,
            Email = registeringUser.Email,
            FirstName = registeringUser.FirstName,
            LastName = registeringUser.LastName,
            SecurityStamp = Guid.NewGuid().ToString(),
        };
        
        var result = await userManager.CreateAsync(creatingUser, registeringUser.Password);

        if (!result.Succeeded)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, "Unable to create account.");
        }
        
        var newUser = await userManager.FindByEmailAsync(registeringUser.Email);
        var roleResult = await userManager.AddToRoleAsync(newUser, Roles.Tier1);

        if (!roleResult.Succeeded)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, "Unable to add role to user");
        }
        
        return Ok();
    }
    
    [Roles(Roles.Admin)]
    [HttpDelete("Revoke")]
    public async Task<IActionResult> Revoke()
    {
        var email = HttpContext.User.Identity?.Name;
        
        if (email == null)
        {
            return Unauthorized();
        }

        var user = await userManager.FindByEmailAsync(email);

        if (user == null)
        {
            return Unauthorized();
        }

        user.RefreshToken = null;

        await userManager.UpdateAsync(user);

        return Ok();
    }
    
    private async Task<Tuple<string, JwtSecurityToken>> GenerateJwt(string email)
    {
        var user = await userManager.FindByEmailAsync(email);
        
        var userRoles = await userManager.GetRolesAsync(user);
        
        var authClaims = new List<Claim>
        {
            new (ClaimTypes.Name, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        foreach (var userRole in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:Issuer"],
            audience: _configuration["JWT:Audience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return new Tuple<string, JwtSecurityToken>(new JwtSecurityTokenHandler().WriteToken(token), token);
    }
    
    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];

        using var generator = RandomNumberGenerator.Create();
        
        generator.GetBytes(randomNumber);

        return Convert.ToBase64String(randomNumber);
    }
    
    private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
    {
        var audience = _configuration.GetValue<string>("JWT:Audience");
        var issuer = _configuration.GetValue<string>("JWT:Issuer");
        var key = _configuration.GetValue<string>("JWT:Key");

        
        var validation = new TokenValidationParameters()
        {
            ValidAudience = audience,
            ValidIssuer = issuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
            ValidateLifetime = false
        };

        return new JwtSecurityTokenHandler().ValidateToken(token, validation, out _);
    }
}