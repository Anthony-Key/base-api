using System.Text;
using System.Text.Json.Serialization;
using ArneuraAPI.Data;
using IDriveApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace IDriveApi
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseLazyLoadingProxies().UseSqlServer(Configuration.GetConnectionString("DatabaseConnection"));
            });
            
            // Add Identity
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
            }).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
            services.AddAuthentication(auth =>
            {
                auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.SaveToken = true;
                options.RequireHttpsMetadata = false;

                var audience = Configuration.GetValue<string>("JWT:Audience");
                var issuer = Configuration.GetValue<string>("JWT:Issuer");
                var key = Configuration.GetValue<string>("JWT:Key");

                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = audience,
                    ValidIssuer = issuer,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                    ClockSkew = new TimeSpan(0,0,5)
                };
            });
            
            services.AddAuthorization();

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "IDrive",
                    Version = "v1"
                });
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 1safsfsdfdfd\"",
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                    {
                        new OpenApiSecurityScheme {
                            Reference = new OpenApiReference {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] {}
                    }
                });
            });

            services.AddCors(options => options.AddPolicy("CorsPolicy",
                builder =>
                {
                    builder.AllowAnyHeader()
                        .AllowAnyMethod()
                        .SetIsOriginAllowed((host) => true)
                        .AllowCredentials();
                }
            ));
            
            services.AddInjections();
            services.AddControllers().AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.PropertyNamingPolicy = null;
                options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
            });
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();
        }
        
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ApplicationDbContext dbContext, IDbInitializer dbInitializer)
        {
            dbContext.Database.Migrate();
            dbInitializer.Initialize();

            app.UseHttpsRedirection();
            
            app.UseStaticFiles();
            app.UseRouting();
            app.UseCors("CorsPolicy");
            app.UseAuthentication();
            app.UseAuthorization();

            if (env.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
                app.UseDeveloperExceptionPage();
                /*app.UseHangfireDashboard("/hangfire", new DashboardOptions
                {
                    Authorization = new[] { new MyAuthorizationFilter() }
                });*/
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}