namespace VLTPAuth
{
  public interface IEEXAuthService
  {
    bool IsAuthorized(string ssn, string pin);
  }
}