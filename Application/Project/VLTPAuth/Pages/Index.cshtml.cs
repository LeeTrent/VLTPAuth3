using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace VLTPAuth.Pages
{
    public class IndexModel : PageModel
    {
        // public void OnGet()
        // {
        //   return RedirectToPage("/Account/Login", new { area = "Identity" });
        // }

        public IActionResult OnGet() 
        { 
          return RedirectToPage("/Account/Login", new { area = "Identity" }); 
}         
    }
}
