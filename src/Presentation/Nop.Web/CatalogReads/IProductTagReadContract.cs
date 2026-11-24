namespace Nop.Web.CatalogReads;

/// <summary>
/// Represents the product tag read contract
/// </summary>
public partial interface IProductTagReadContract
{
    /// <summary>
    /// Get product tags with the number of products visible in the current request context
    /// </summary>
    /// <param name="limit">The number of most used tags to return; pass 0 to get all tags</param>
    /// <returns>
    /// A task that represents the asynchronous operation
    /// The task result contains the product tags and the reader that answered
    /// </returns>
    Task<ProductTagReadResult> GetProductTagsAsync(int limit = 0);
}