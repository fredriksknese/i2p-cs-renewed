using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;
using I2PRouterWeb.Services;

namespace I2PRouterWeb.Pages;

public class IndexModel : PageModel
{
    private readonly RouterService _routerService;

    public RouterStatistics RouterStats { get; set; } = new();
    public IEnumerable<ActivityLogEntry> RecentActivity { get; set; } = Array.Empty<ActivityLogEntry>();
    public string FormattedUptime { get; set; } = string.Empty;

    public IndexModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public void OnGet()
    {
        LoadData();
    }

    public IActionResult OnPostStart()
    {
        _routerService.StartRouter();
        return RedirectToPage();
    }

    public IActionResult OnPostStop()
    {
        _routerService.StopRouter();
        return RedirectToPage();
    }

    public IActionResult OnPostStartProxy()
    {
        _routerService.StartHttpProxy();
        return RedirectToPage();
    }

    public IActionResult OnPostStopProxy()
    {
        _routerService.StopHttpProxy();
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostReseed()
    {
        await _routerService.ReseedAsync();
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostManualReseed(IFormFile reseedFile)
    {
        if (reseedFile != null && reseedFile.Length > 0)
        {
            using (var ms = new MemoryStream())
            {
                await reseedFile.CopyToAsync(ms);
                var count = await _routerService.ReseedFromFileAsync(ms.ToArray());
                TempData["ReseedMessage"] = $"Reseed successful: {count} routers imported.";
            }
        }
        else
        {
            TempData["ReseedMessage"] = "Please select a valid .su3 or .zip file.";
        }
        return RedirectToPage();
    }

    private void LoadData()
    {
        RouterStats = _routerService.GetStatistics();
        RecentActivity = _routerService.GetActivityLog().Take(10);

        var uptime = RouterStats.Uptime;
        FormattedUptime = uptime.Days > 0
            ? $"{uptime.Days}d {uptime.Hours}h {uptime.Minutes}m"
            : $"{uptime.Hours}h {uptime.Minutes}m {uptime.Seconds}s";
    }
}
