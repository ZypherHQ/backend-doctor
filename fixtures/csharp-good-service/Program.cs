using Microsoft.AspNetCore.Builder;
using Microsoft.Data.SqlClient;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
    options.AddPolicy("trusted", policy =>
        policy.WithOrigins("https://admin.example.com").AllowAnyHeader().AllowAnyMethod()));
var app = builder.Build();
var admin = app.MapGroup("/admin").RequireAuthorization();

admin.MapGet("/users/{id:int}", (int id, string? includeProfile) =>
{
    if (id <= 0) return Results.BadRequest(new { error = "id must be positive" });
    using var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(3) };
    using var command = UserQueries.FindById(id);
    return Results.Ok(new { id, includeProfile, command.CommandText, client.Timeout });
}).RequireAuthorization();

admin.MapPost("/users", (CreateUserRequest request) =>
    string.IsNullOrWhiteSpace(request.Email)
        ? Results.BadRequest(new { error = "email is required" })
        : Results.Created($"/admin/users/{request.Id}", request)).RequireAuthorization();

app.Run();

public record CreateUserRequest(int Id, string Email);

static class UserQueries
{
    public static SqlCommand FindById(int id)
    {
        var command = new SqlCommand("SELECT Id, Email FROM Users WHERE Id = @id");
        command.Parameters.AddWithValue("@id", id);
        return command;
    }
}
