namespace UserAuth.Entities
{
    public class LoginDto
    {
        public string UserNameOrEmailOrPhone { get; set; } = null!;

        public string Password { get; set; } = null!;
    }
}
    