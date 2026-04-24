using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PCore.TunnelLayer;
using System.Collections.Generic;

namespace I2PRouterWeb.Pages
{
    public class TunnelBuildLogsModel : PageModel
    {
        public IEnumerable<TunnelBuildLogger.LogEntry> LogEntries { get; private set; }

        public void OnGet()
        {
            LogEntries = TunnelBuildLogger.Inst.GetEntries();
        }
    }
}
