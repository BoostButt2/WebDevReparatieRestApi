using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AimTrainerRestApi.Data;
using AimTrainerRestApi.Models;
using System.Diagnostics;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Net.Http.Headers;
using System.Runtime.ConstrainedExecution;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;

namespace AimTrainerRestApi.Controllers
{
/*    [Authorize]*/
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AimTrainerDbContext _context;

        public UserController(AimTrainerDbContext context)
        {
            _context = context;
        }

        //Get all users
        // GET: api/User
        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<User>>> GetUser()
        {
          if (_context.User == null)
          {
              return NotFound();
          }
            return await _context.User.ToListAsync();
        }

        //Get user by id
        // GET: api/User/5
        [HttpGet("{id}")]
        public async Task<ActionResult<User>> GetUser(Guid id)
        {
          if (_context.User == null)
          {
              return NotFound();
          }
            var user = await _context.User.FindAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }

        //Get user by username
        // GET: api/User/getbyusername/{username}
        [HttpGet("getbyusername/{username}")]
        public async Task<ActionResult<User>> GetUser(string username)
        {
            if (!ConfirmUser(username))
            {
                return Unauthorized();
            }
            if (_context.User == null)
            {
                return NotFound();
            }
            var user = _context.User.Where(x => x.Username == username).FirstOrDefault();

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }

        //Edit user
        // PUT: api/User
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost("edit")]
        public async Task<IActionResult> PutUser(User user)
        {
/*            var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.ReadJwtToken(token);

            var claims = jwtToken.Claims;*/

            Guid userId = GetUserIdFromToken();
            user = CleanUser(user);
            user.Password = HashString(user.Password, user.Username);
            var dbUser = _context.User.Where(x => x.Userid == userId).FirstOrDefault();
            dbUser.Username = user.Username;
            dbUser.Password = user.Password;

            _context.Entry(dbUser).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserExists(userId))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        //Create new user
        // POST: api/User/create
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [AllowAnonymous]
        [HttpPost("create")]
        public async Task<ActionResult<User>> PostUser(User user)
        {
            user = CleanUser(user);
            user.Password = HashString(user.Password, user.Username);
            user.Userid = Guid.NewGuid();
            user.Role = "player";

            User dbUserOnUsername = _context.User.Where(x => x.Username == user.Username).FirstOrDefault();
            User dbUserOnEmail = _context.User.Where(x => x.Email == user.Email).FirstOrDefault();

            if (!IsValidEmail(user.Email) || !checkMaxLength(user))
            {
                return Problem("Invalid input. Naughty naughty");
            }
            if (_context.User == null)
            {
                return Problem("Entity set 'AimTrainerDbContext.User'  is null.");
            }
            if (dbUserOnUsername != null)
            {
                return Problem("Username already exists");
            }
            if (dbUserOnEmail != null)
            {
                return Problem("Email already exists");
            }
            _context.User.Add(user);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetUser", new { id = user.Userid }, user);
        }

        // DELETE: api/User/5
        [AllowAnonymous]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            if (_context.User == null)
            {
                return NotFound();
            }
            var user = await _context.User.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            _context.User.Remove(user);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // POST login: api/User/login
        [HttpPost("login")]
        public async Task<IActionResult> CheckLogin(User user)
        {
            string hashedInputPassword = HashString(user.Password, user.Userid.ToString());
            User dbUserOnUsername = _context.User.Where(x => x.Username == user.Username).FirstOrDefault();
            if(dbUserOnUsername != null)
            {
                if(dbUserOnUsername.Password == hashedInputPassword)
                {                    

                    return Ok("Login is succesful");
                }
            }
            return Problem("Username and password don't match");
        }

        [HttpPost("checkloggedin")]
        public async Task<IActionResult> CheckLoggedIn(User user)
        {
            if (!ConfirmUser(user.Username))
            {
                return Unauthorized();
            }
            return Ok();
        }

        [Authorize(Roles = "admin")]
        [HttpGet("checkadmin")]
        public async Task<ActionResult<IEnumerable<User>>> cbeckAdmin()
        {
            return Ok();
        }


        [HttpPost("updatescore")]
        public async Task<IActionResult> UpdateScore(User user)
        {
            if (!ConfirmUser(user.Username))
            {
                return Problem();
            }
            try
            {
                if (_context.User.Where(x => x.Username == user.Username).FirstOrDefault().Score < user.Score)
                {
                    _context.User.Where(x => x.Username == user.Username).FirstOrDefault().Score = user.Score;
                    await _context.SaveChangesAsync();
                    return Ok("Highscore: " + user.Score.ToString());
                }
                return BadRequest();

            }
            catch
            {
                return Problem();
            }
        }

        private bool ConfirmUser(string username)
        {
            var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.ReadJwtToken(token);

            var claims = jwtToken.Claims;

            string tokenUsername = claims.FirstOrDefault(c => c.Type == "Username")?.Value;

            if (tokenUsername == username)
            {
                return true;
            }
            return false;
        }

        private Guid GetUserIdFromToken()
        {
            var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.ReadJwtToken(token);

            var claims = jwtToken.Claims;

            Guid userId = Guid.Parse(claims.FirstOrDefault(c => c.Type == "Userid")?.Value);

            return userId;
        }

        private bool UserExists(Guid id)
        {
            return (_context.User?.Any(e => e.Userid == id)).GetValueOrDefault();
        }

        bool IsValidEmail(string email)
        {
            var trimmedEmail = email.Trim();

            if (trimmedEmail.EndsWith("."))
            {
                return false; // suggested by @TK-421
            }
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == trimmedEmail;
            }
            catch
            {
                return false;
            }
        }

        private bool checkMaxLength(User user)
        {

            int maxLength = 2048;
            if (user.Email.Length <= maxLength || user.Username.Length <= maxLength)
            {
                return true;
            }
            return false;
        }

        //Removes forbidden characters from a string
        public static string CleanString(string strIn)
        {
            // Replace invalid characters with empty strings.
            return Regex.Replace(strIn, @"[^\w\.@-]", "");
        }

        //Makes user input safe to store in the database
        public static User CleanUser(User user)
        {
            user.Username = CleanString(user.Username).Trim();

            return user;
        }

        public static string HashString(string text, string salt)
        {
            if (String.IsNullOrEmpty(text))
            {
                return String.Empty;
            }

            // Uses SHA256 to create the hash
            using (var sha = new System.Security.Cryptography.SHA256Managed())
            {
                // Convert the string to a byte array first, to be processed
                byte[] textBytes = System.Text.Encoding.UTF8.GetBytes(text + salt);
                byte[] hashBytes = sha.ComputeHash(textBytes);

                // Convert back to a string, removing the '-' that BitConverter adds
                string hash = BitConverter
                    .ToString(hashBytes)
                    .Replace("-", String.Empty);

                return hash;
            }
        }
    }
}
