
using ArneuraAPI.Data;
using ArneuraAPI.Extensions;
using IDriveApi;
using Microsoft.AspNetCore.Hosting;

namespace ArneuraAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Migrate<ApplicationDbContext>().Run();
        }

        private static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}