using IncidentResponseDemo.Services;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// podesavanje seriloga za strukturirano sigurnosno logiranje u fajl
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("incident_logs.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

builder.Services.AddControllers();
builder.Services.AddSingleton<IncidentTrackerService>(); 

var app = builder.Build();

app.UseAuthorization();
app.MapControllers();

app.Run();