// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

//namespace Microsoft.AspNetCore.Identity.UI.Pages.Account.Manage.Internal
namespace VLTPAuth.Areas.Identity.Pages.Account.Manage
{
    public class ShowRecoveryCodesModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<LoginWith2faModel> _logger;

        public ShowRecoveryCodesModel
        (
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,  
            ILogger<LoginWith2faModel> logger
        )
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        [TempData]
        public string[] RecoveryCodes { get; set; }

        [TempData]
        public string StatusMessage { get; set; }

        public IActionResult OnGet()
        {
            if (RecoveryCodes == null || RecoveryCodes.Length == 0)
            {
                return RedirectToPage("./TwoFactorAuthentication");
            }

            return Page();
        }
        public async Task<IActionResult> OnPostAsync()
        {
            // _logger.LogInformation("[ShowRecoveryCodesModel][OnPost] => Calling _signInManager.GetTwoFactorAuthenticationUserAsync()");
            // var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            // if (user == null)
            // {
            //     throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            // }

            _logger.LogInformation("[ShowRecoveryCodesModel][OnPost] => Calling _userManager.GetUserAsync(User)");
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new InvalidOperationException($"[ShowRecoveryCodesModel][OnPost] => Call to _userManager.GetUserAsync(User) returned null.");
            }

            _logger.LogInformation("[ShowRecoveryCodesModel][OnPost] => Calling _signInManager.SignOutAsync()");
            await _signInManager.SignOutAsync();

            _logger.LogInformation("[ShowRecoveryCodesModel][OnPost] => Redirecting to VLTP website");
            return Redirect(string.Format("https://apps.ocfo.gsa.gov/ords/volta/volta.volta_main?id={0}", user.Id));
        }
    }
}