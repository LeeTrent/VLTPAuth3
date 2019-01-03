using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace VLTPAuth.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginWith2faModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LoginWith2faModel> _logger;

        public LoginWith2faModel(SignInManager<IdentityUser> signInManager, ILogger<LoginWith2faModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public bool RememberMe { get; set; }

        public string ReturnUrl { get; set; }

        public class InputModel
        {
            [Required]
            [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Text)]
            [Display(Name = "Authenticator code")]
            public string TwoFactorCode { get; set; }

            [Display(Name = "Remember this machine")]
            public bool RememberMachine { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(bool rememberMe, string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            ReturnUrl = returnUrl;
            RememberMe = rememberMe;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(bool rememberMe, string returnUrl = null)
        {
            _logger.LogInformation("[LoginWith2fa][OnPost] => BEGIN ...");

            if (!ModelState.IsValid)
            {
                return Page();
            }

            returnUrl = returnUrl ?? Url.Content("~/");
            _logger.LogInformation("[LoginWith2fa][OnPost] => returnUrl: " + returnUrl);

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var authenticatorCode = Input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
            _logger.LogInformation("[LoginWith2fa][OnPost] => authenticatorCode: " + authenticatorCode);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, Input.RememberMachine);
            _logger.LogInformation("[LoginWith2fa][OnPost] => TwoFactorAuthenticatorSignIn.Succeeded: " + result.Succeeded);
            
            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", user.Id);
                //return LocalRedirect(returnUrl);
                 //return RedirectToPage("./LoginWith2faSuccess");
                 //return Redirect("https://nytimes.com?ID=F9ADS79SD8AF9SAD8FF9S0");
                // https://apps.ocfo.gsa.gov/ords/volta/volta.volta_main
                //return Redirect("https://apps.ocfo.gsa.gov/ords/volta/volta.volta_main?id=A1DF8FDS989DDKJSHFDSJ");
                
                _logger.LogInformation("[LoginWith2fa][OnPost] => Calling _signInManager.SignOutAsync()");
                await _signInManager.SignOutAsync();
                
                _logger.LogInformation("[LoginWith2fa][OnPost] => Redirecting to VLTP website");
                return Redirect(string.Format("https://apps.ocfo.gsa.gov/ords/volta/volta.volta_main?id={0}", user.Id));
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID '{UserId}' account locked out.", user.Id);
                return RedirectToPage("./Lockout");
            }
            else
            {
                _logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return Page();
            }
        }  
    }
}
