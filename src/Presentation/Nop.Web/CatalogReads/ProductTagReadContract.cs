using System.Globalization;
using Nop.Core;
using Nop.Core.Domain.Catalog;
using Nop.Services.Customers;
using Nop.Web.Factories;
using ILogger = Nop.Services.Logging.ILogger;

namespace Nop.Web.CatalogReads;

/// <summary>
/// Represents the product tag read contract that routes reads to the catalog reads service when enabled
/// </summary>
public partial class ProductTagReadContract : IProductTagReadContract
{
    #region Fields

    protected readonly CatalogReadsHttpClient _catalogReadsHttpClient;
    protected readonly CatalogSettings _catalogSettings;
    protected readonly ICatalogModelFactory _catalogModelFactory;
    protected readonly ICustomerService _customerService;
    protected readonly ILogger _logger;
    protected readonly IStoreContext _storeContext;
    protected readonly IWorkContext _workContext;

    #endregion

    #region Ctor

    public ProductTagReadContract(CatalogReadsHttpClient catalogReadsHttpClient,
        CatalogSettings catalogSettings,
        ICatalogModelFactory catalogModelFactory,
        ICustomerService customerService,
        ILogger logger,
        IStoreContext storeContext,
        IWorkContext workContext)
    {
        _catalogReadsHttpClient = catalogReadsHttpClient;
        _catalogSettings = catalogSettings;
        _catalogModelFactory = catalogModelFactory;
        _customerService = customerService;
        _logger = logger;
        _storeContext = storeContext;
        _workContext = workContext;
    }

    #endregion

    #region Utilities

    /// <summary>
    /// Resolve the request scope from the current request context and settings
    /// </summary>
    /// <param name="limit">The number of most used tags to return; 0 means all</param>
    /// <returns>
    /// A task that represents the asynchronous operation
    /// The task result contains the request scope
    /// </returns>
    protected virtual async Task<ProductTagReadRequest> PrepareRequestAsync(int limit)
    {
        var store = await _storeContext.GetCurrentStoreAsync();
        var customer = await _workContext.GetCurrentCustomerAsync();
        var roleIds = await _customerService.GetCustomerRoleIdsAsync(customer);
        var language = await _workContext.GetWorkingLanguageAsync();

        return new ProductTagReadRequest(
            StoreId: _catalogSettings.IgnoreStoreLimitations ? 0 : store.Id,
            RoleIds: roleIds,
            IgnoreAcl: _catalogSettings.IgnoreAcl || roleIds.Length == 0,
            LanguageId: language.Id,
            Culture: CultureInfo.CurrentCulture.Name,
            Limit: limit);
    }

    /// <summary>
    /// Read product tags with the .NET reference implementation
    /// </summary>
    /// <param name="limit">The number of most used tags to return; 0 means all</param>
    /// <returns>
    /// A task that represents the asynchronous operation
    /// The task result contains the product tags
    /// </returns>
    protected virtual async Task<ProductTagReadResult> ReadWithDotNetAsync(int limit)
    {
        var model = await _catalogModelFactory.PreparePopularProductTagsModelAsync(limit);
        var items = model.Tags
            .Select(tag => new ProductTagReadItem(tag.Id, tag.Name, tag.SeName, tag.ProductCount))
            .ToList();

        return new ProductTagReadResult(items, ProductTagReadBackend.DotNet);
    }

    #endregion

    #region Methods

    /// <summary>
    /// Get product tags with the number of products visible in the current request context
    /// </summary>
    /// <param name="limit">The number of most used tags to return; pass 0 to get all tags</param>
    /// <returns>
    /// A task that represents the asynchronous operation
    /// The task result contains the product tags and the reader that answered
    /// </returns>
    public virtual async Task<ProductTagReadResult> GetProductTagsAsync(int limit = 0)
    {
        if (!_catalogSettings.ProductTagsRust)
            return await ReadWithDotNetAsync(limit);

        try
        {
            var items = await _catalogReadsHttpClient.GetProductTagsAsync(await PrepareRequestAsync(limit));

            return new ProductTagReadResult(items, ProductTagReadBackend.Rust);
        }
        catch (Exception exception)
        {
            await _logger.WarningAsync($"Catalog reads service failed to serve product tags, answering from .NET: {exception.Message}", exception);

            return await ReadWithDotNetAsync(limit);
        }
    }

    #endregion
}
