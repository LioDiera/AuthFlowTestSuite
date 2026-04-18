using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SweetSalesAPI.Controllers;

public record StoreSettings(string StoreName, string Address, string Currency, decimal TaxRate);

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SettingsController : ControllerBase
{
    private static StoreSettings _settings = new("Sweet Sales", "123 Bakery Lane", "$", 8m);

    [HttpGet]
    public ActionResult<StoreSettings> Get() => Ok(_settings);

    [HttpPut]
    public ActionResult<StoreSettings> Put([FromBody] StoreSettings settings)
    {
        _settings = settings;
        return Ok(_settings);
    }
}
