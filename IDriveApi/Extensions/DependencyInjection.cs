using ArneuraAPI.Data;

namespace IDriveApi;

public static class DependencyInjection
{
    public static IServiceCollection AddInjections(this IServiceCollection services)
    {
        //Database Initialization
        services.AddScoped<IDbInitializer, DbInitializer>();
        return services;
    }
}