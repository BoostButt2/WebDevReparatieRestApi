using System.ComponentModel.DataAnnotations;

namespace AimTrainerRestApi.Models
{
    public class User
    {
        [Key]
        public Guid Userid { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
        public int Score { get; set; }
        public string Email { get; set; }
    }
}
