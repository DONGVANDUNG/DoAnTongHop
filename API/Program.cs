using System.Text;
using API.Data;
using API.Extentions;
using API.Interfaces;
using API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<DataContext>(opt=>{
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
});
builder.Services.AddCors();
builder.Services.AddApplicationServices(builder.Configuration);
builder.Services.AddScoped<ITokenService,TokenService>();
builder.Services.AddIdentityServices(builder.Configuration);
var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseCors(builder=> builder.AllowAnyHeader().AllowAnyMethod()
     .WithOrigins("http://localhost:4200"));

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
