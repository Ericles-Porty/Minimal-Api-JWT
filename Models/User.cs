namespace MinimalApiAuth.Models;
public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string Role { get; set; } = null!;
}