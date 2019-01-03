using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
 using Microsoft.AspNetCore.Mvc.RazorPages;

namespace VLTPAuth.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginWith2faModelSuccessModel : PageModel
    {
      public void OnGet()
      {
      }      
    }
}
