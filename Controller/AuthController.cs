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
using LoginApi.Services;

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
    private string GenerateVerificationToken()
    {
         return Guid.NewGuid().ToString("N");
    }
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly EmailService _emailService;

    public AuthController(
    AppDbContext context,
    IConfiguration configuration,
    EmailService emailService)
{
    _context = context;
    _configuration = configuration;
    _emailService = emailService;
}
    [HttpGet]
    public IActionResult Test()
    {
        return Ok(new { Message = "DbContext Injected Successfully" });
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto request)
    {
        var existingUser = _context.Users
            .FirstOrDefault(u => u.Username == request.Username);

        if (existingUser != null)
        {
            return BadRequest(new { Message = "Username already exists" });
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
        var verificationToken = GenerateVerificationToken();
        Console.WriteLine($"TOKEN SAVED: {verificationToken}");
        var emailTokenEntity = new EmailVerificationToken
        {
            UserId = user.Id,
            Token = verificationToken,
            Expiry = DateTime.UtcNow.AddDays(1)
        };
        _context.EmailVerificationTokens.Add(emailTokenEntity);

        await _context.SaveChangesAsync();

        var verifyLink =
            $"http://192.168.1.15:5062/api/auth/verify-email?token={verificationToken}";

        await _emailService.SendEmailAsync(
            user.Email,
            "Verify Your Account",
            $"""
            <h2>Welcome {user.Username}</h2>

            <p>Thank you for registering.</p>

            <p>Click the button below to verify your email:</p>

            <a href="{verifyLink}">
                Verify Email
            </a>
            """
        );

        return Content(
            """
            <html>
                <body style="font-family:Arial;text-align:center;padding-top:50px;">
                    <h1> Email Verified Successfully</h1>
                    <p>You can now return to the app and login.</p>
                </body>
            </html>
            """,
            "text/html"
        );
    }
    [HttpPost("login")]
    public IActionResult Login(LoginDto request)
    {
        var user = _context.Users
            .FirstOrDefault(u => u.Username == request.Username);

        if (user == null)
        {
            return Unauthorized(new { Message = "Invalid Username" });
        }
        if (!user.EmailVerified)
        {
            return Unauthorized(new { Message = "Please verify your email before logging in" });
        }

        bool isValid = BCrypt.Net.BCrypt.Verify(
            request.Password,
            user.PasswordHash
        );

        if (!isValid)
        {
            return Unauthorized(new { Message = "Invalid Password" });
        }
        var jwt = GenerateJwtToken(user);

        var refreshToken = GenerateVerificationToken();
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
        return Ok(new
        {
            Message = "Welcome to protected profile"
        });
    }
    [Authorize(Roles = "admin")]
    [HttpGet("admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new
        {
            Message = "Welcome Admin"
        });
    }
    [HttpPost("refresh")]
    public IActionResult Refresh(RefreshTokenDto request)
    {
        var tokenEntity = _context.RefreshTokens
            .FirstOrDefault(rt => rt.Token == request.RefreshToken);
        if (tokenEntity == null || tokenEntity.IsRevoked || tokenEntity.Expiry < DateTime.UtcNow)
        {
            return Unauthorized(new { Message = "Invalid Refresh Token" });
        }
        var user = _context.Users.FirstOrDefault(u => u.Id == tokenEntity.UserId);
        if (user == null)
        {
            return Unauthorized(new { Message = "User not found" });
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
            return Unauthorized(new { Message = "Invalid Refresh Token" });
        }
        tokenEntity.IsRevoked = true;
        _context.SaveChanges();
        return Ok(new
        {
            Message = "Logged out successfully"
        });
    }
    [HttpGet("verify-email")]
    public IActionResult VerifyEmail(string token)
    {
        Console.WriteLine($"TOKEN RECEIVED: {token}");
        var emailTokenEntity = _context.EmailVerificationTokens
            .FirstOrDefault(evt => evt.Token == token && evt.Expiry > DateTime.UtcNow);

        if (emailTokenEntity == null)
        {
            return Unauthorized(new { Message = "Invalid or expired verification token" });
        }

        var user = _context.Users.FirstOrDefault(u => u.Id == emailTokenEntity.UserId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        user.EmailVerified = true;
        _context.EmailVerificationTokens.Remove(emailTokenEntity);
        _context.SaveChanges();

        return Ok(new
        {
            Message = "Email verified successfully"
        });
    }
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDto request)
    {
        var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);
        if (user == null)
        {
            return NotFound(new { Message = "User with given email not found" });
        }
        var resetToken = GenerateVerificationToken();
        var passwordResetEntity = new PasswordResetToken
        {
            UserId = user.Id,
            Token = resetToken,
            Expiry = DateTime.UtcNow.AddHours(1)
        };
        _context.PasswordResetTokens.Add(passwordResetEntity);
        _context.SaveChanges();

        await _emailService.SendEmailAsync(
            user.Email,
            "Reset Your Password",
            $"""
            <h2>Password Reset Request</h2>

            <p>Your password reset token is:</p>

            <h3>{resetToken}</h3>

            <p>This token expires in 1 hour.</p>
            """
        );

        return Ok(new
        {
            Message = "Password reset email sent successfully"
        });
    }
    [HttpPost("reset-password")]
    public IActionResult ResetPassword(ResetPasswordDto request)
    {
        var resetTokenEntity = _context.PasswordResetTokens
            .FirstOrDefault(prt => prt.Token == request.ResetToken && prt.Expiry > DateTime.UtcNow);

        if (resetTokenEntity == null)
        {
            return Unauthorized(new { Message = "Invalid or expired password reset token" });
        }

        var user = _context.Users.FirstOrDefault(u => u.Id == resetTokenEntity.UserId);
        if (user == null)
        {
            return NotFound(new { Message = "User not found" });
        }

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        _context.PasswordResetTokens.Remove(resetTokenEntity);
        _context.SaveChanges();

        return Ok(new
        {
            Message = "Password reset successfully"
        });
    }
}