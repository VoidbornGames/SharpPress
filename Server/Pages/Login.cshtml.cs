using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SharpPress.Models;
using SharpPress.Services;
using System.ComponentModel.DataAnnotations;

namespace SharpPress.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public InputModel Input { get; set; }

        private readonly Logger _logger;
        private readonly FeatherDatabase _database;
        private readonly AuthenticationService _authService;

        public string? SuccessMessage { get; set; }
        public string? ErrorMessage { get; set; }

        public LoginModel(FeatherDatabase database, AuthenticationService authService, Logger logger)
        {
            _database = database;
            _authService = authService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var isLoggedIn = await _database.GetByColumn<User>("Username", User.Identity?.Name);
            if (isLoggedIn != null)
                return Redirect("/");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string return_url = "")
        {
            if (!ModelState.IsValid)
                return Page();

            try
            {
                var user = await _database.GetByColumn<User>("Email", Input.Email);
                if (user == null || !_authService.VerifyPassword(Input.Password, user.Password))
                {
                    ErrorMessage = "ایمیل یا رمز عبور اشتباه است.";
                    return Page();
                }

                user.LastLogin = DateTime.UtcNow;
                await _database.SaveData(user);

                string token = _authService.GenerateJwtToken(user);
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Expires = DateTime.UtcNow.AddHours(168),
                    Secure = false,
                    SameSite = SameSiteMode.Lax
                };
                Response.Cookies.Append("X-Access-Token", token, cookieOptions);

                if (user.HasRole(UserRole.Admin))
                    return Redirect(string.IsNullOrWhiteSpace(return_url) ? "/admin" : return_url);

                return Redirect(string.IsNullOrWhiteSpace(return_url) ? "/" : return_url);
            }
            catch (Exception ex)
            {
                ErrorMessage = "خطای سرور";
                _logger.LogError($"OnPostLogin Error: {ex.Message}");
                return Page();
            }
        }

        public class InputModel
        {
            [Required(ErrorMessage = "ایمیل الزامی است")]
            [EmailAddress(ErrorMessage = "ایمیل معتبر نیست")]
            public string Email { get; set; } = "";

            [Required(ErrorMessage = "رمز عبور الزامی است")]
            [DataType(DataType.Password)]
            public string Password { get; set; } = "";

            public bool RememberMe { get; set; }
        }
    }
}