using LoginApi.Data;
using Microsoft.AspNetCore.Mvc;
using LoginApi.DTOs;
using LoginApi.Models;
using System.IdentityModel.Tokens.Jwt;   // For generating JWT tokens
using System.Security.Claims;            // For creating claims for the JWT token
using System.Text;                       // For encoding the secret key used in JWT token generation
using Microsoft.IdentityModel.Tokens; // For creating signing credentials for the JWT token
using Microsoft.AspNetCore.Authorization;  // For adding authorization attributes to controller actions (if needed)
using System.Security.Cryptography;

namespace LoginApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim("UserId", user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)
        );
        var creds = new SigningCredentials(
            key,
            SecurityAlgorithms.HmacSha256
        );
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(3),
            signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    private string GenerateEmailVerificationToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;

    public AuthController(AppDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }
    [HttpGet]
    public IActionResult Test()
    {
        return Ok("DbContext Injected Successfully");
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto request)
    {
        var existingUser = _context.Users
            .FirstOrDefault(u => u.Username == request.Username);

        if (existingUser != null)
        {
            return BadRequest("Username already exists");
        }

        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role = request.Role,
            EmailVerified = false
        };

        _context.Users.Add(user);

        await _context.SaveChangesAsync();
        var verificationToken = GenerateEmailVerificationToken();
        var emailTokenEntity = new EmailVerificationToken
        {
            UserId = user.Id,
            Token = verificationToken,
            Expiry = DateTime.UtcNow.AddDays(1)
        };
        _context.EmailVerificationTokens.Add(emailTokenEntity);

        await _context.SaveChangesAsync();
        return Ok(new { Message = "User Registered", EmailVerificationToken = verificationToken });
    }
    [HttpPost("login")]
    public IActionResult Login(LoginDto request)
    {
        var user = _context.Users
            .FirstOrDefault(u => u.Username == request.Username);

        if (user == null)
        {
            return Unauthorized("Invalid Username");
        }
        if (!user.EmailVerified)
        {
            return Unauthorized("Please verify your email before logging in");
        }

        bool isValid = BCrypt.Net.BCrypt.Verify(
            request.Password,
            user.PasswordHash
        );

        if (!isValid)
        {
            return Unauthorized("Invalid Password");
        }
        var jwt = GenerateJwtToken(user);

        var refreshToken = GenerateRefreshToken();
        var refreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshToken,
            Expiry = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };
        _context.RefreshTokens.Add(refreshTokenEntity);
        _context.SaveChanges();

        return Ok(new
        {
            AccessToken = jwt,
            RefreshToken = refreshToken
        });
    }
    [Authorize]
    [HttpGet("profile")]
    public IActionResult Profile()
    {
        return Ok("Welcome to protected profile");
    }
    [Authorize(Roles = "admin")]
    [HttpGet("admin")]
    public IActionResult AdminOnly()
    {
        return Ok("Welcome Admin");
    }
    [HttpPost("refresh")]
    public IActionResult Refresh(RefreshTokenDto request)
    {
        var tokenEntity = _context.RefreshTokens
            .FirstOrDefault(rt => rt.Token == request.RefreshToken);
        if (tokenEntity == null || tokenEntity.IsRevoked || tokenEntity.Expiry < DateTime.UtcNow)
        {
            return Unauthorized("Invalid Refresh Token");
        }
        var user = _context.Users.FirstOrDefault(u => u.Id == tokenEntity.UserId);
        if (user == null)
        {
            return Unauthorized("User not found");
        }
        var jwt = GenerateJwtToken(user);
        return Ok(new
        {
            AccessToken = jwt
        });
    }
    [HttpPost("logout")]
    public IActionResult Logout(RefreshTokenDto request)
    {
        var tokenEntity = _context.RefreshTokens
            .FirstOrDefault(rt => rt.Token == request.RefreshToken);
        if (tokenEntity == null)
        {
            return Unauthorized("Invalid Refresh Token");
        }
        tokenEntity.IsRevoked = true;
        _context.SaveChanges();
        return Ok("Logged out successfully");
    }
    [HttpGet("verify-email")]
    public IActionResult VerifyEmail(string token)
    {
        var emailTokenEntity = _context.EmailVerificationTokens
            .FirstOrDefault(evt => evt.Token == token && evt.Expiry > DateTime.UtcNow);

        if (emailTokenEntity == null)
        {
            return Unauthorized("Invalid or expired verification token");
        }

        var user = _context.Users.FirstOrDefault(u => u.Id == emailTokenEntity.UserId);
        if (user == null)
        {
            return NotFound("User not found");
        }

        user.EmailVerified = true;
        _context.EmailVerificationTokens.Remove(emailTokenEntity);
        _context.SaveChanges();

        return Ok("Email verified successfully");
    }
    [HttpPost("forgot-password")]
    public IActionResult ForgotPassword(ForgotPasswordDto request)
    {
        var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);
        if (user == null)
        {
            return NotFound("User with given email not found");
        }
        var resetToken = GenerateEmailVerificationToken();
        var passwordResetEntity = new PasswordResetToken
        {
            UserId = user.Id,
            Token = resetToken,
            Expiry = DateTime.UtcNow.AddHours(1)
        };
        _context.PasswordResetTokens.Add(passwordResetEntity);
        _context.SaveChanges();
        return Ok(new
        {
            ResetToken = resetToken
        });
    }
    [HttpPost("reset-password")]
    public IActionResult ResetPassword(ResetPasswordDto request)
    {
        var resetTokenEntity = _context.PasswordResetTokens
            .FirstOrDefault(prt => prt.Token == request.ResetToken && prt.Expiry > DateTime.UtcNow);

        if (resetTokenEntity == null)
        {
            return Unauthorized("Invalid or expired password reset token");
        }

        var user = _context.Users.FirstOrDefault(u => u.Id == resetTokenEntity.UserId);
        if (user == null)
        {
            return Ok(
                "If the email exists, a reset link has been sent."
            );
        }

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        _context.PasswordResetTokens.Remove(resetTokenEntity);
        _context.SaveChanges();

        return Ok("Password reset successfully");
    }
}