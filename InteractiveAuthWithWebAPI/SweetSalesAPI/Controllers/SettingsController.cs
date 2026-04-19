using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SweetSalesAPI.Controllers;

// Single record that represents the store's configurable settings.
// Currency and TaxRate are kept here so the SPA can apply them consistently
// across all price displays without hard-coding them in JavaScript.
public record StoreSettings(string StoreName, string Address, string Currency, decimal TaxRate);

[ApiController]
[Route("api/[controller]")]
[Authorize] // Requires a valid JWT — settings are only visible to authenticated users
public class SettingsController : ControllerBase
{
    // In-memory default; replaced when the user saves from the Settings tab.
    private static StoreSettings _settings = new("Sweet Sales", "123 Bakery Lane", "$", 8m);

    // GET api/settings — returns current settings; called on SPA load
    [HttpGet]
    public ActionResult<StoreSettings> Get() => Ok(_settings);

    // PUT api/settings — full replacement; returns the saved settings so the
    // SPA can update its local state from the server response in one round-trip
    [HttpPut]
    public ActionResult<StoreSettings> Put([FromBody] StoreSettings settings)
    {
        _settings = settings;
        return Ok(_settings);
    }
}
