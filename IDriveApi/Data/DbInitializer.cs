using IDriveApi.Controllers;
using IDriveApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace ArneuraAPI.Data
{
    public interface IDbInitializer
    {
        void Initialize();
    }

    public class DbInitializer : IDbInitializer
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public DbInitializer(IConfiguration configuration, ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _configuration = configuration;
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public void Initialize()
        {
            string superadminEmail = _configuration.GetValue<string>("SuperUser:Email");
            string superadminFirstName = _configuration.GetValue<string>("SuperUser:FirstName");
            string superadminLastName = _configuration.GetValue<string>("SuperUser:LastName");
            string superadminPassword = _configuration.GetValue<string>("SuperUser:Password");
            string superadminDefaultRole = _configuration.GetValue<string>("SuperUser:Role");
            string DefaultRoles = _configuration.GetValue<string>("DefaultRoles");
            ApplicationUser? user = _userManager.FindByEmailAsync(superadminEmail).Result;
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = $"{superadminFirstName}.{superadminLastName}",
                    FirstName = superadminFirstName,
                    LastName = superadminLastName,
                    Email = superadminEmail,
                    EmailConfirmed = true,
                };
                _ = _userManager.CreateAsync(user, superadminPassword).Result;
            }
            string[] roles = DefaultRoles.Split(';');
            foreach (var r in roles)
            {
                IdentityRole? newRole = _roleManager.FindByNameAsync(r).Result;
                if (newRole == null)
                {
                    newRole = new IdentityRole
                    {
                        Name = r
                    };
                    _ = _roleManager.CreateAsync(newRole).Result;
                }
            }
            user = _userManager.FindByEmailAsync(superadminEmail).Result;
            if (user != null && !_userManager.IsInRoleAsync(user, Roles.Admin).Result)
            {
                _ = _userManager.AddToRoleAsync(user, superadminDefaultRole).Result;
            }
        }
    }
}
