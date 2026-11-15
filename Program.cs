using IncidentResponseDemo.Services;
using Serilog;

// Structured security logging to the console and a daily rolling file.
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("security_incidents.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();

builder.Services.AddControllers();
builder.Services.Configure<BruteForceOptions>(builder.Configuration.GetSection(BruteForceOptions.SectionName));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IncidentTrackerService>();

var app = builder.Build();

app.MapControllers();
app.Run();
