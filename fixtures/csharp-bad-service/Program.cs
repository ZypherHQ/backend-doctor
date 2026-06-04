using Microsoft.AspNetCore.Builder;
using Microsoft.Data.SqlClient;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader()));
var app = builder.Build();

app.MapGet("/admin/users/{id}", (string id) =>
{
    var client = new HttpClient();
    using var command = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}");
    return "ok";
});

app.Run();
