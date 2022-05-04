using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Primitives;

namespace FuncOnVS
{
    public static class GithubWebhookFn
    {
        [FunctionName("GithubWebhookFn")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            string githubSignature = req.Headers["x-hub-signature"];


            if(!IsAuthorize(githubSignature, requestBody))
            {
                return new UnauthorizedObjectResult(null);
            }
            

            return new OkObjectResult(requestBody);
        }

        public static bool IsAuthorize(string signature, string content)
        {
            string key = "lesamel";

            byte[] keyByte = Encoding.UTF8.GetBytes(key);
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);

            byte[] hashmessage = new HMACSHA1(keyByte).ComputeHash(contentBytes);
            var contentHexitsStr = String.Concat(Array.ConvertAll(hashmessage, x => x.ToString("x2")));

            var computedSignature = $"sha1={contentHexitsStr}";

            return signature == computedSignature;
        }
    }
}
