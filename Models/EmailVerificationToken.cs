namespace LoginApi.Models;
public class EmailVerificationToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTime Expiry { get; set; }
    public User User { get; set; } = null!;
}