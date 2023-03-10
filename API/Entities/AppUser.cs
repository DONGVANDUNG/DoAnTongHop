using System.ComponentModel.DataAnnotations;

namespace API.Entities
{
    public class AppUser
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string UserName { get; set; }
        public byte[] PassWordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}