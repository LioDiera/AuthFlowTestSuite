using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SweetSalesAPI.Controllers;

public record InventoryItem(int Id, string Name, string Category, string Emoji, decimal Price, int Stock);
public record UpsertInventoryItem(string Name, string Category, string Emoji, decimal Price, int Stock);

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class InventoryController : ControllerBase
{
    // In-memory store — seeded with the same items shown in the POS page
    private static readonly List<InventoryItem> _items =
    [
        new(1,  "Butter Croissant",  "Pastries", "🥐", 3.50m,  24),
        new(2,  "Pretzel Twist",     "Pastries", "🥨", 2.75m,  18),
        new(3,  "Glazed Donut",      "Pastries", "🍩", 2.25m,  30),
        new(4,  "Belgian Waffle",    "Pastries", "🧇", 5.00m,   8),
        new(5,  "Everything Bagel",  "Pastries", "🥯", 3.00m,  15),
        new(6,  "Lemon Danish",      "Pastries", "🍋", 4.25m,  12),
        new(7,  "Pain au Chocolat",  "Pastries", "🍫", 4.00m,  10),
        new(8,  "Almond Croissant",  "Pastries", "🥐", 3.75m,  20),
        new(9,  "Chocolate Cake",    "Cakes",    "🎂", 28.00m,  5),
        new(10, "Snickerdoodle",     "Cookies",  "🍪", 1.50m,  50),
        new(11, "Sourdough Loaf",    "Breads",   "🥖", 8.00m,   7),
        new(12, "Vanilla Cupcake",   "Cupcakes", "🧁", 3.25m,  22),
        new(13, "Apple Pie",         "Pies",     "🥧", 14.00m,  4),
        new(14, "Flat White",        "Drinks",   "☕", 4.50m,  99),
    ];

    private static int _nextId = 15;

    // GET api/inventory
    [HttpGet]
    public ActionResult<IEnumerable<InventoryItem>> GetAll() => Ok(_items);

    // GET api/inventory/{id}
    [HttpGet("{id:int}")]
    public ActionResult<InventoryItem> Get(int id)
    {
        var item = _items.FirstOrDefault(i => i.Id == id);
        return item is null ? NotFound() : Ok(item);
    }

    // POST api/inventory
    [HttpPost]
    public ActionResult<InventoryItem> Create([FromBody] UpsertInventoryItem dto)
    {
        var item = new InventoryItem(_nextId++, dto.Name, dto.Category, dto.Emoji, dto.Price, dto.Stock);
        _items.Add(item);
        return CreatedAtAction(nameof(Get), new { id = item.Id }, item);
    }

    // PUT api/inventory/{id}
    [HttpPut("{id:int}")]
    public IActionResult Update(int id, [FromBody] UpsertInventoryItem dto)
    {
        int idx = _items.FindIndex(i => i.Id == id);
        if (idx < 0) return NotFound();
        _items[idx] = new InventoryItem(id, dto.Name, dto.Category, dto.Emoji, dto.Price, dto.Stock);
        return NoContent();
    }

    // DELETE api/inventory/{id}
    [HttpDelete("{id:int}")]
    public IActionResult Delete(int id)
    {
        int idx = _items.FindIndex(i => i.Id == id);
        if (idx < 0) return NotFound();
        _items.RemoveAt(idx);
        return NoContent();
    }
}
