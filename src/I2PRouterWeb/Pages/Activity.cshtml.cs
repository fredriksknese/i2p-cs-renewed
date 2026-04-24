using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PRouterWeb.Services;

namespace I2PRouterWeb.Pages;

public class ActivityModel : PageModel
{
    private readonly RouterService _routerService;

    public IEnumerable<ActivityLogEntry> ActivityLog { get; set; } = Array.Empty<ActivityLogEntry>();
    public IEnumerable<string> Categories { get; set; } = Array.Empty<string>();
    public string? SelectedCategory { get; set; }
    public int TotalEntries { get; set; }

    public ActivityModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public void OnGet(string? category)
    {
        SelectedCategory = category;
        
        var allActivity = _routerService.GetActivityLog();
        
        // Get unique categories
        Categories = allActivity
            .Select(a => a.Category)
            .Distinct()
            .OrderBy(c => c)
            .ToList();

        // Filter by category if specified
        if (!string.IsNullOrEmpty(category))
        {
            ActivityLog = allActivity.Where(a => a.Category == category).ToList();
        }
        else
        {
            ActivityLog = allActivity.ToList();
        }

        TotalEntries = ActivityLog.Count();
    }
}
