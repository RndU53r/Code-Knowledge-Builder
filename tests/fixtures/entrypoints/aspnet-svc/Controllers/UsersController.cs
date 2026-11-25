using System.Data.SqlClient;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Users
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UsersController : ControllerBase
    {
        [HttpGet("{id}")]
        public IActionResult Get(int id, [FromQuery] string name)
        {
            var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = '{name}'");
            return Ok(cmd);
        }

        [HttpPost]
        public IActionResult Create([FromBody] string payload)
        {
            var cmd = new SqlCommand("INSERT INTO Users (Name) VALUES (@name)");
            return Ok();
        }

        [HttpPost("run")]
        public IActionResult Run([FromQuery] string tool)
        {
            Process.Start(tool, "--version");
            return Ok();
        }

        [AllowAnonymous]
        [HttpPost("load")]
        public IActionResult Load()
        {
            var bf = new BinaryFormatter();
            return Ok(bf);
        }
    }
}
