using Newtonsoft.Json;

namespace Nop.Web.CatalogReads;

/// <summary>
/// Represents a product tag with its localized name, slug and the number of visible products
/// </summary>
/// <param name="Id">Product tag identifier</param>
/// <param name="Name">Localized product tag name</param>
/// <param name="SeName">Search engine friendly name (slug)</param>
/// <param name="ProductCount">Number of products visible to the current customer in the current store</param>
public partial record ProductTagReadItem(
    [property: JsonProperty("id", Required = Required.Always)] int Id,
    [property: JsonProperty("name", Required = Required.Always)] string Name,
    [property: JsonProperty("seName", Required = Required.Always)] string SeName,
    [property: JsonProperty("productCount", Required = Required.Always)] int ProductCount);
