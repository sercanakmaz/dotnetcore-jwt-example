using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthenticationAuthorization.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrderController : ControllerBase
    {
        public static List<string> Values = new List<string>();
        // GET api/values
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] {"value1", "value2"};
        }

        [Authorize(OrderPermissions.CanReadOrder)]
        [Authorize()]
        // GET api/values/5
        [HttpGet("{id}")]
        public ActionResult<string> Get(int id)
        {
            return "value";
        }

        // POST api/values
        [Authorize(OrderPermissions.CanCreateOrder)]
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        [Authorize(OrderPermissions.CanApproveFraud)]
        public void FraudApproved(int id, [FromBody] string value)
        {
        }
    }

    public class OrderPermissions
    {
        public const string CanReadOrder = "CanReadOrder";
        public const string CanCreateOrder = "CanCreateOrder";
        public const string CanApproveFraud = "CanApproveFraud";
    }
}