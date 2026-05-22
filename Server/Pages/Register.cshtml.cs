using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SharpPress.Models;
using SharpPress.Services;
using System.ComponentModel.DataAnnotations;

namespace SharpPress.Pages
{
    public class RegisterModel : PageModel
    {
        [BindProperty]
        public InputModel Input { get; set; }

        private readonly Logger logger;
        private readonly FeatherDatabase database;
        private readonly AuthenticationService authService;

        public string SuccessMessage { get; set; }
        public string ErrorMessage { get; set; }


        public RegisterModel(FeatherDatabase _database, AuthenticationService authentication, Logger _logger)
        {
            logger = _logger;
            database = _database;
            authService = authentication;
        }

        public async Task<IActionResult> OnGet()
        {
            var isLogedIn = await database.GetByColumn<User>("Username", User.Identity.Name);
            if (isLogedIn != null)
            {
                return Redirect("/");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string return_url = "")
        {
            if (!ModelState.IsValid)
            {
                foreach (var modelStateKey in ModelState.Keys)
                {
                    var modelStateVal = ModelState[modelStateKey];
                    foreach (var error in modelStateVal.Errors)
                    {
                        logger.LogError($"ModelState Error - Key: {modelStateKey}, Error: {error.ErrorMessage}");
                    }
                }
                return Page();
            }

            try
            {
                var user = await database.GetByColumn<User>("Email", Input.Email);
                if (user != null)
                {
                    ErrorMessage = "کاربر با این ایمیل وجود دارد.";
                    return Page();
                }

                var userNamed = await database.GetByColumn<User>("Username", Input.Username);
                if (userNamed != null)
                {
                    ErrorMessage = "کاربر با این یوزرنیم وجود دارد.";
                    return Page();
                }

                if (Input.Username.Contains(" "))
                {
                    ErrorMessage = "یوزرنیم شما دارای فضای خالی است.";
                    return Page();
                }

                if (Input.Password != Input.ConfirmPassword)
                {
                    ErrorMessage = "رمز ها با هم متفاوت هستند.";
                    return Page();
                }

                var newUser = new User
                {
                    Username = Input.Username,
                    Email = Input.Email,
                    Password = authService.HashPassword(Input.Password),
                    UUID = Guid.NewGuid().ToString("N")
                };
                await database.SaveData(newUser);

                logger.Log($"🤳 New User Registered! Email: {newUser.Email}");

                string token = authService.GenerateJwtToken(newUser);
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Expires = DateTime.UtcNow.AddHours(168),
                    Secure = false,
                    SameSite = SameSiteMode.Lax
                };
                Response.Cookies.Append("X-Access-Token", token, cookieOptions);

                return Redirect(string.IsNullOrWhiteSpace(return_url) ? "/" : return_url);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "ایمیل یا یوزرنیم از قبل وجود دارد!");
                logger.LogError($"OnPostRegister Error: {ex.Message}");
                return Page();
            }
        }

        public class InputModel
        {
            [Required]
            public string Username { get; set; }

            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Compare("Password", ErrorMessage = "رمز عبور و تکرار آن مطابقت ندارند.")]
            public string ConfirmPassword { get; set; }

            [Range(typeof(bool), "true", "true", ErrorMessage = "برای ثبت‌نام باید قوانین و مقررات را بپذیرید.")]
            public bool AcceptTerms { get; set; }
        }
    }
}