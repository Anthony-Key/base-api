using Microsoft.EntityFrameworkCore;

namespace ArneuraAPI.Extensions
{
    public static class MigrateDatabase
    {
        public static IHost Migrate<T>(this IHost webHost) where T : DbContext
        {
            var serviceScopeFactory = (IServiceScopeFactory)webHost
                .Services.GetService(typeof(IServiceScopeFactory));

            using (var scope = serviceScopeFactory.CreateScope())
            {
                var services = scope.ServiceProvider;

                var dbContext = services.GetRequiredService<T>();
                dbContext.Database.Migrate();
            }

            return webHost;
        }
    }
}