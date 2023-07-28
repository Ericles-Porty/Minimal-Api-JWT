using MinimalApiAuth.Models;

namespace MinimalApiAuth.Repositories
{
    public static class UserRepository
    {
        public static User Get(string Name, string Password)
        {
            var users = new List<User>();
            users.Add(new User { Id = 1, Name = "batman", Password = "batman", Role = "admin" });
            users.Add(new User { Id = 2, Name = "robin", Password = "robin", Role = "employee" });
            var user = users.FirstOrDefault(x => x.Name.ToLower() == Name.ToLower());
            return user;
        }
    }
}