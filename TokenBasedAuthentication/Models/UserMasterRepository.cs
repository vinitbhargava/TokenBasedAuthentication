using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TokenBasedAuthentication.Models
{
    public class UserMasterRepository : IDisposable
    {
        WEBAPI_TOKEN_Bases_AuthEntities context = new WEBAPI_TOKEN_Bases_AuthEntities();

        //This method is used to check and validate the user credentials
        public UserMaster ValidateUser(string username, string password)
        {
            return context.UserMasters.FirstOrDefault(user =>
            user.UserName.Equals(username, StringComparison.OrdinalIgnoreCase)
            && user.UserPassword == password);
        }

        //This method is used to check and validate the Client credentials
        public ClientMaster ValidateClient(string ClientID, string ClientSecret)
        {
            return context.ClientMasters.FirstOrDefault(user =>
             user.ClientId == ClientID
            && user.ClientSecret == ClientSecret);
        }

        public void Dispose()
        {
            context.Dispose();
        }
    }
}