namespace VLTPAuth
{
  public class EEXAuthService : IEEXAuthService
  {
    public bool IsAuthorized(string ssn, string pin)
    {
      return true;
    }
  }
}