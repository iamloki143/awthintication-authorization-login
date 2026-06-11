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

        if (existingUser != null) return BadRequest(new { Message = "Username already exists" });

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
        var emailTokenEntity = new EmailVerificationToken
        {
            UserId = user.Id,
            Token = verificationToken,
            Expiry = DateTime.UtcNow.AddDays(1)
        };
        _context.EmailVerificationTokens.Add(emailTokenEntity);

        var verifyLink = $"http://192.168.1.15:5062/api/auth/verify-email?token={verificationToken}";

        try
        {
            await _emailService.SendEmailAsync(
                user.Email,
                "Verify Your Account",
                $"""
                <h2>Welcome {user.Username}!</h2>
                <p>Thank you for registering.</p>
                <p>Your verification code is:</p>
                <h2 style="letter-spacing:4px">{verificationToken}</h2>
                <p>Enter this code in the app to verify your account.</p>
                <p>This code expires in 24 hours.</p>
                """
            );

            await _context.SaveChangesAsync();

            return Ok(new { Message = "Registration successful! Please check your email to verify your account." });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending email: {ex.Message}");

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            return StatusCode(500, new { Message = "Registration failed: could not send verification email. Please try again." });
        }
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
            RefreshToken = refreshToken,
            Role = user.Role,       
            Email = user.Email,     
            Username = user.Username
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
    [HttpPost("verify-email")]
    public IActionResult VerifyEmail(EmailVerificationDto request)
    {
        var emailTokenEntity = _context.EmailVerificationTokens
            .FirstOrDefault(evt => evt.Token == request.Token && evt.Expiry > DateTime.UtcNow);

        if (emailTokenEntity == null)
            return Unauthorized(new { Message = "Invalid or expired verification token" });

        var user = _context.Users.FirstOrDefault(u => u.Id == emailTokenEntity.UserId);
        if (user == null)
            return NotFound(new { Message = "User not found" });

        user.EmailVerified = true;
        _context.EmailVerificationTokens.Remove(emailTokenEntity);
        _context.SaveChanges();

        return Ok(new { Message = "Email verified successfully" });
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
    [HttpPost("resend-verification")]
    public async Task<IActionResult> ResendVerification(ForgotPasswordDto request)
    {
        var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);
        if (user == null)
            return NotFound(new { Message = "User not found" });

        if (user.EmailVerified)
            return BadRequest(new { Message = "Email already verified" });

        var oldToken = _context.EmailVerificationTokens
            .FirstOrDefault(t => t.UserId == user.Id);
        if (oldToken != null)
        {
            _context.EmailVerificationTokens.Remove(oldToken);
        }

        var verificationToken = GenerateVerificationToken();
        _context.EmailVerificationTokens.Add(new EmailVerificationToken
        {
            UserId = user.Id,
            Token = verificationToken,
            Expiry = DateTime.UtcNow.AddDays(1)
        });

        try
        {
            await _emailService.SendEmailAsync(
                user.Email,
                "Verify Your Account",
                $"""
                <h2>Welcome {user.Username}!</h2>
                <p>Your new verification code is:</p>
                <h2>{verificationToken}</h2>
                <p>This code expires in 24 hours.</p>
                """
            );
            await _context.SaveChangesAsync();
            return Ok(new { Message = "Verification email resent" });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error resending email: {ex.Message}");
            return StatusCode(500, new { Message = "Failed to send email" });
        }
    }
}