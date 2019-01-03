using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VLTPAuth.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace VLTPAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Database Connection String:");
            Console.WriteLine(Configuration.GetSection("ConnectionStrings")["DefaultConnection"]);
            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Logging:");
            Console.WriteLine(Configuration.GetSection("Logging"));
            Console.WriteLine("----------------------------------------------------------------");            
            Console.WriteLine("Logging:LogLevel:");
            Console.WriteLine(Configuration.GetSection("Logging:LogLevel"));
            Console.WriteLine("----------------------------------------------------------------");            
            Console.WriteLine("Logging:LogLevel:Default:");
            Console.WriteLine(Configuration.GetSection("Logging:LogLevel:Default"));
            Console.WriteLine("----------------------------------------------------------------");  
            Console.WriteLine("(\"Logging:LogLevel\")[\"Default\"]:");
            Console.WriteLine(Configuration.GetSection("Logging:LogLevel")["Default"]);
            Console.WriteLine("----------------------------------------------------------------");                       
            Console.WriteLine("AllowedHosts:");
            Console.WriteLine(Configuration.GetSection("AllowedHosts"));
            Console.WriteLine("----------------------------------------------------------------");     
            Console.WriteLine("AllowedHosts<string>:");
            Console.WriteLine(Configuration.GetValue<string>("AllowedHosts"));
            Console.WriteLine("----------------------------------------------------------------");                     

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddDefaultIdentity<IdentityUser>()
                .AddEntityFrameworkStores<ApplicationDbContext>();

            //////////////////////////////////////////////////////   
            // Register EEX Authorization Service
            //////////////////////////////////////////////////////               
            services.AddScoped<IEEXAuthService, EEXAuthService>();  
            //////////////////////////////////////////////////////   

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            app.UseMvc();
        }
    }
}
