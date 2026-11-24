using System.Globalization;
using Newtonsoft.Json;
using Nop.Core;
using Nop.Core.Domain.Catalog;

namespace Nop.Web.CatalogReads;

/// <summary>
/// Represents the HTTP client to request the catalog reads service
/// </summary>
public partial class CatalogReadsHttpClient
{
    #region Fields

    protected readonly CatalogSettings _catalogSettings;
    protected readonly HttpClient _httpClient;

    #endregion

    #region Ctor

    public CatalogReadsHttpClient(CatalogSettings catalogSettings,
        HttpClient client)
    {
        client.Timeout = TimeSpan.FromSeconds(3);

        _catalogSettings = catalogSettings;
        _httpClient = client;
    }

    #endregion

    #region Methods

    /// <summary>
    /// Get product tags from the catalog reads service
    /// </summary>
    /// <param name="request">Resolved request scope</param>
    /// <returns>
    /// A task that represents the asynchronous operation
    /// The task result contains the product tags in their final order
    /// </returns>
    public virtual async Task<IList<ProductTagReadItem>> GetProductTagsAsync(ProductTagReadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!Uri.TryCreate(_catalogSettings.CatalogReadsServiceUrl, UriKind.Absolute, out var serviceUri))
            throw new NopException($"Catalog reads service URL '{_catalogSettings.CatalogReadsServiceUrl}' is not a valid absolute URL");

        var roleIds = string.Join(',', request.RoleIds.Select(id => id.ToString(CultureInfo.InvariantCulture)));
        var query = FormattableString.Invariant(
            $"storeId={request.StoreId}&roleIds={roleIds}&ignoreAcl={(request.IgnoreAcl ? "true" : "false")}&languageId={request.LanguageId}&culture={Uri.EscapeDataString(request.Culture)}&limit={request.Limit}");

        using var response = await _httpClient.GetAsync(new Uri(serviceUri, $"/api/catalog/product-tags?{query}"));
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync();

        return JsonConvert.DeserializeObject<List<ProductTagReadItem>>(body)
            ?? throw new NopException("Catalog reads service returned an empty product tag body");
    }

    #endregion
}
