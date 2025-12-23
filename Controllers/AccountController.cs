using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserAuth.Entities;
using UserAuth.Models;

namespace UserAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly ILogger<AccountController> _logger;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration config, ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
            _logger = logger;
        }

        [HttpGet("Admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminAction()
        {
            _logger.LogInformation("Admin action accessed by user: {UserName}", User.Identity?.Name);
            return Ok("Admin action accessed.");
        }

        [HttpGet("User")]
        [Authorize(Roles = "User")]
        public IActionResult UserAction()
        {
            _logger.LogInformation("User action accessed");
            return Ok("User action accessed.");
        }

        [HttpGet("generate-reset-token")]
        public async Task<IActionResult> GenerateResetToken([FromQuery] string email)
        {
            //find the user by email
            IdentityUser? user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return BadRequest(new { Message = "User Not Found" });
            }

            //Generate password reset token
            string token = await _userManager.GeneratePasswordResetTokenAsync(user);

            return Ok(new { Token = token });
        }

        [HttpPost("register")]
        [AllowAnonymous] //allows user to register without authentication
        public async Task<IActionResult> RegisterAsync(RegisterDto model)
        {
            _logger.LogInformation("Registration attempt for user: {UserName}", model.UserName);
            bool userData = await _userManager.Users.AnyAsync(u => u.UserName == model.UserName || u.Email == model.Email);
            if (userData)
            {
                _logger.LogWarning("Registration failed: User with username {UserName} or email {Email} already exists.", model.UserName, model.Email);
                return Conflict(new DefaultResponseModel()
                {
                    Success = false,
                    Statuscode = StatusCodes.Status409Conflict,
                    Message = "User with the same username or email already exists.",
                    Data = null
                });
            }

            IdentityUser user = new()   //IdentityUser is the foundational class for managing users, handling authentication (login/logout), authorization (permissions), storing core user data (username, password hash, email), and integrating with features like roles, claims, and external logins, saving you from building complex security systems from scratch and allowing easy extension with custom properties
            {
                UserName = model.UserName,
                Email = model.Email,
                LockoutEnabled = true // enable lockout for new users
            };

            IdentityResult result = await _userManager.CreateAsync(user, model.Password); //asp.net identity automatically hashes the password
            if (!result.Succeeded)
            {
                _logger.LogError("Registration failed for user: {UserName}", model.UserName);
                return BadRequest(new DefaultResponseModel()
                {
                    Success = false,
                    Statuscode = StatusCodes.Status400BadRequest,
                    Message = "User registration failed.",
                    Data = result.Errors
                });
            }

            if (!string.IsNullOrEmpty(model.Role))
            {
                await _userManager.AddToRoleAsync(user, model.Role);
            }
            _logger.LogInformation("User registered successfully: {UserName}", model.UserName);
            return Ok("User registered successfully.");
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginAsync(LoginDto model)
        {
            _logger.LogInformation("Login attempt for user: {UserNameOrEmailOrPhone}", model.UserNameOrEmailOrPhone);

            //check if the identifer is email,username or phone
            IdentityUser? user = null;

            //check if email
            if (model.UserNameOrEmailOrPhone.Contains("@"))
            {
                user = await _userManager.FindByEmailAsync(model.UserNameOrEmailOrPhone);
            }
            else
            {
                user = model.UserNameOrEmailOrPhone.Length >= 10
                    ? await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == model.UserNameOrEmailOrPhone)
                    : await _userManager.FindByNameAsync(model.UserNameOrEmailOrPhone);
            }

            if (user == null)
            {
                _logger.LogWarning("Login failed: User not found for identifier {UserNameOrEmailOrPhone}", model.UserNameOrEmailOrPhone);
                return Unauthorized("Invalid username,email, or phone number.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("User account locked out for identifier: {Identifier}", model.UserNameOrEmailOrPhone);
                return Unauthorized("User account is locked out.");
            }

            Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
            if (!result.Succeeded)
            {
                _ = await _userManager.AccessFailedAsync(user);

                if (await _userManager.GetAccessFailedCountAsync(user) >= 3)
                {
                    _ = await _userManager.SetLockoutEnabledAsync(user, true);
                    _ = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(5));
                }

                _logger.LogWarning("Invalid login attempt with identifier: {Identifier}", model.UserNameOrEmailOrPhone);

                return Unauthorized("Invalid Email or Password.");
            }

            _ = await _userManager.ResetAccessFailedCountAsync(user);

            (string token, string refreshToken, DateTime refreshTokenExpiry) = await GenerateJwtToken(user);
            _logger.LogInformation("User with identifier {Identifier} logged in successfully", model.UserNameOrEmailOrPhone);
            return Ok(new { token, refreshToken, refreshTokenExpiry });
        }

        private async Task<(string, string, DateTime)> GenerateJwtToken(IdentityUser user)
        {
            IConfigurationSection jwtSettings = _config.GetSection("Jwt");
            SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key is not found")));
            SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
            };

            IList<string> roles = await _userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            JwtSecurityToken token = new(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(3),
                signingCredentials: creds
            );

            (string refreshToken, DateTime refreshTokenExpiry) = GenerateRefreshToken();
            //Always update the refresh token in storage
            _ = await _userManager.SetAuthenticationTokenAsync(user, "UserAuth", "RefreshToken", refreshToken);
            _ = await _userManager.SetAuthenticationTokenAsync(user, "UserAuth", "RefreshTokenExpiry", refreshTokenExpiry.ToString());

            return (new JwtSecurityTokenHandler().WriteToken(token), refreshToken, refreshTokenExpiry);
        }

        private (string, DateTime) GenerateRefreshToken()
        {
            byte[] randomNumber = new byte[32];
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            string refreshToken = Convert.ToBase64String(randomNumber);
            DateTime refreshTokenExpiry = DateTime.UtcNow.AddMinutes(3); //Set refresh toke to expire in 3 minutes
            return (refreshToken, refreshTokenExpiry);
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh(TokenRequestDto tokenRequest)
        {
            _logger.LogInformation("Token refresh attempt");
            if (tokenRequest == null || string.IsNullOrEmpty(tokenRequest.RefreshToken) || string.IsNullOrEmpty(tokenRequest.AccessToken))
            {
                _logger.LogWarning("Token refresh failed: Invalid token request");
                return BadRequest("Invalid client request");
            }

            ClaimsPrincipal? principal = GetPrincipalFromExpiredToken(tokenRequest.AccessToken);
            if (principal == null)
            {
                _logger.LogWarning("Invalid token refresh request: Could not extract claims");

                return BadRequest("Invalid client request: Could not extract claims.");
            }
            string? userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                _logger.LogWarning("Invalid token refresh request: User ID not found");

                return BadRequest("Invalid client request: User ID not found.");
            }

            IdentityUser? user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("Invalid token refresh request: User not found");

                return BadRequest("Invalid client request: User not found.");
            }

            if (!await ValidateRefreshToken(user, tokenRequest.RefreshToken))
            {
                _logger.LogWarning("Invalid token refresh request: Refresh token validation failed");
                return BadRequest("Invalid client request: Refresh token validation failed.");
            }

            //generate new token
            (string newAccessToken, string newRefreshToken, DateTime refreshTokenExpiry) = await GenerateJwtToken(user);
            _logger.LogInformation("Token Refresh Successfully!");

            return Ok(new
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                RefreshTokenExpiry = refreshTokenExpiry
            });
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto model)
        {
            _logger.LogInformation("Resetting password for email: {Email}", model.Email);

            IdentityUser? user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogWarning("User with email {Email} not found", model.Email);
                return BadRequest(new { message = "User Not Found" });
            }

            IdentityResult result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to reset Password for email {Email}", model.Email);
                return BadRequest(new { message = "Faild to reset Password", errors = result.Errors });
            }

            _logger.LogInformation("Password successfully reset for email: {Email}", model.Email);
            return Ok(new { message = "Password reset successfully!" });
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            try
            {
                TokenValidationParameters tokenValidationParameters = new()
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key is not found"))),
                    ValidateLifetime = false //we want to get claims from expired token as well
                };

                JwtSecurityTokenHandler tokenHandler = new();
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

                if (securityToken is not JwtSecurityToken jwtToken ||
                   !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogWarning("Invalid token!");
                    return null;
                }

                Claim? expiryClaim = principal.FindFirst(JwtRegisteredClaimNames.Exp);
                if (expiryClaim != null && long.TryParse(expiryClaim.Value, out long expValue))
                {
                    DateTime expiryDate = DateTimeOffset.FromUnixTimeSeconds(expValue).UtcDateTime;
                    if (expiryDate > DateTime.UtcNow)
                    {
                        _logger.LogWarning("Token has not expired yet.");
                        return null;
                    }
                }
                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                return null;
            }
        }

        private async Task<bool> ValidateRefreshToken(IdentityUser user, string refreshToken)
        {
            string? storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "UserAuth", "RefreshToken");
            string? storedRefreshTokenExpiry = await _userManager.GetAuthenticationTokenAsync(user, "UserAuth", "RefreshTokenExpiry");

            if (string.IsNullOrEmpty(storedRefreshToken) || string.IsNullOrEmpty(storedRefreshTokenExpiry))
            {
                _logger.LogInformation("Stored refresh token or expiry is missing");
                return false;
            }
            // ensure refresh token is not expired
            if (!DateTime.TryParse(storedRefreshTokenExpiry, out DateTime expiryDate) || expiryDate < DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh token is expired");

                return false;//expired
            }

            return storedRefreshToken == refreshToken;
        }
    }
}
