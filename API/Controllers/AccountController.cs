using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.Dtos;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")] // Post : api/account/register?username=dave&password=pwd
        public async Task<ActionResult<UserDto>> Register(RegisterDto users)
        {
            if (await UserExists(users.UserName)) return BadRequest("Username is token");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = users.UserName,
                PassWordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(users.PassWord)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto
              {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
              };
        }

        [HttpPost("login")]
        public async Task<ActionResult<AppUser>> Login(LoginDto login)
        {
                var user = await _context.Users.FirstOrDefaultAsync(e => e.UserName == login.UserName);
                if(user == null) return Unauthorized();

                using var hmac = new HMACSHA512(user.PassWordHash);
                var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(login.PassWord));

                for (int i = 0; i < computeHash.Length; i++)
                {
                       if(computeHash[i] !=user.PassWordHash[i]) return Unauthorized("Invalid password");
                }
                return user;
        }
        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(e => e.UserName == username.ToLower());
        }
    }
}