namespace UserAuth.Entities
{
    public class TokenRequestDto
    {
        public string RefreshToken { get; set; } = null!;
        public string AccessToken { get; set; } = null!; 
    }
}
