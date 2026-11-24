namespace Nop.Web.CatalogReads;

/// <summary>
/// Represents the result of a product tag read
/// </summary>
/// <param name="Items">Product tags in their final order</param>
/// <param name="Backend">Reader that answered</param>
public partial record ProductTagReadResult(IList<ProductTagReadItem> Items, ProductTagReadBackend Backend);
