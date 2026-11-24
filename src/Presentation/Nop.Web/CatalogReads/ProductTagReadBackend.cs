namespace Nop.Web.CatalogReads;

/// <summary>
/// Represents the reader that answered a product tag read
/// </summary>
public enum ProductTagReadBackend
{
    /// <summary>
    /// The .NET reference implementation
    /// </summary>
    DotNet,

    /// <summary>
    /// The catalog reads service
    /// </summary>
    Rust
}
