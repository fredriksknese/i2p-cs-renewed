using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using I2PRouterWeb.Services;

var builder = WebApplication.CreateBuilder(args);

// Configure logging
Logging.ReadAppConfig();
Logging.LogToDebug = false;
Logging.LogToConsole = true;

// Enable file logging - clear existing log file on startup
var logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "logs.txt");
if (File.Exists(logFilePath))
{
    File.Delete(logFilePath);
}
Logging.LogToFile(logFilePath);
Logging.LogInformation($"Logging to file: {logFilePath}");

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddSingleton<NetDbLogService>();
builder.Services.AddSingleton<RouterService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
