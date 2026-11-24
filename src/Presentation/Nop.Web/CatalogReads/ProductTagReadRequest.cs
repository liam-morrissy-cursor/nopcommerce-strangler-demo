namespace Nop.Web.CatalogReads;

/// <summary>
/// Represents the request scope the catalog reads service filters product tags by
/// </summary>
/// <param name="StoreId">Store identifier; 0 means no store restriction</param>
/// <param name="RoleIds">Customer role identifiers for ACL</param>
/// <param name="IgnoreAcl">A value indicating whether to skip the ACL filter</param>
/// <param name="LanguageId">Working language identifier</param>
/// <param name="Culture">Culture name for the name sort; empty means the invariant culture</param>
/// <param name="Limit">Number of most used tags to return; 0 means all</param>
public partial record ProductTagReadRequest(int StoreId, IList<int> RoleIds, bool IgnoreAcl, int LanguageId, string Culture, int Limit);
