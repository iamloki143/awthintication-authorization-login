using LoginApi.Models;
namespace LoginApi.Models;

public class RefreshToken
{
    public int Id { get; set; }
    public User User { get; set; } = null!;
    public int UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTime Expiry { get; set; }
    public bool IsRevoked { get; set; }
}