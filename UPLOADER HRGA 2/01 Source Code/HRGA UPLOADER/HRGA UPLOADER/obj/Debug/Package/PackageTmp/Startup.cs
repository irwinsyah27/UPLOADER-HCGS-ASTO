using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute("HCGSConfig" ,typeof(HRGA_UPLOADER.Startup))]
namespace HRGA_UPLOADER
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
