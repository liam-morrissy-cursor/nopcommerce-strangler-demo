using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Linq.Expressions;
using System.Net;
using System.Net.Sockets;
using System.Text;
using AwesomeAssertions;
using AwesomeAssertions.Execution;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Nop.Core;
using Nop.Core.Caching;
using Nop.Core.Domain.Catalog;
using Nop.Core.Domain.Customers;
using Nop.Core.Domain.Localization;
using Nop.Core.Domain.Security;
using Nop.Core.Domain.Seo;
using Nop.Core.Domain.Stores;
using Nop.Data;
using Nop.Services.Configuration;
using Nop.Services.Customers;
using Nop.Services.Localization;
using Nop.Web.CatalogReads;
using NUnit.Framework;

namespace Nop.Tests.Nop.Web.Tests.Public;

/// <summary>
/// Runs the shared product tag fixture (rust/catalog-reads/fixtures/product_tags.json) against IProductTagReadContract.
/// With PRODUCT_TAGS_RUST=on the contract talks to the real catalog-reads binary over a snapshot of the test database.
/// </summary>
[TestFixture]
public class ProductTagReadContractTests : WebTest
{
    private const string BUILD_COMMAND = "cargo build --manifest-path rust/catalog-reads/Cargo.toml";

    private static readonly Lazy<FixtureFile> _fixture = new(() =>
        JsonConvert.DeserializeObject<FixtureFile>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "product_tags.json"))));

    private static readonly bool _rustMode = Environment.GetEnvironmentVariable("PRODUCT_TAGS_RUST") == "on";

    private readonly List<Func<Task>> _restoreAfterFixture = new();
    private readonly List<Func<Task>> _cleanupAfterTest = new();

    private INopDataProvider _dataProvider;
    private ISettingService _settingService;
    private IStaticCacheManager _staticCacheManager;
    private IWorkContext _workContext;
    private ICustomerService _customerService;
    private ILanguageService _languageService;
    private Store _currentStore;
    private Customer _originalCustomer;
    private int? _originalCustomerLanguageId;
    private Language _originalLanguage;
    private bool _originalIgnoreAcl;
    private bool _originalIgnoreStoreLimitations;
    private bool _originalProductTagsRust;
    private string _originalServiceUrl;
    private bool _productTagsRustSettingExisted;
    private bool _serviceUrlSettingExisted;

    public static IEnumerable<TestCaseData> Scenarios() =>
        _fixture.Value.Scenarios.Select((scenario, index) => new TestCaseData(index).SetArgDisplayNames(scenario.Name));

    [OneTimeSetUp]
    public async Task OneTimeSetUp()
    {
        _dataProvider = GetService<INopDataProvider>();
        _settingService = GetService<ISettingService>();
        _staticCacheManager = GetService<IStaticCacheManager>();
        _workContext = GetService<IWorkContext>();
        _customerService = GetService<ICustomerService>();
        _languageService = GetService<ILanguageService>();

        _currentStore = await GetService<IStoreContext>().GetCurrentStoreAsync();
        _originalCustomer = await _workContext.GetCurrentCustomerAsync();
        _originalCustomerLanguageId = _originalCustomer.LanguageId;
        _originalLanguage = await _workContext.GetWorkingLanguageAsync();

        var catalogSettings = GetService<CatalogSettings>();
        _originalIgnoreAcl = catalogSettings.IgnoreAcl;
        _originalIgnoreStoreLimitations = catalogSettings.IgnoreStoreLimitations;
        _originalProductTagsRust = catalogSettings.ProductTagsRust;
        _originalServiceUrl = catalogSettings.CatalogReadsServiceUrl;
        _productTagsRustSettingExisted = await _settingService.SettingExistsAsync(catalogSettings, settings => settings.ProductTagsRust);
        _serviceUrlSettingExisted = await _settingService.SettingExistsAsync(catalogSettings, settings => settings.CatalogReadsServiceUrl);

        (await _languageService.GetAllLanguagesAsync()).Should()
            .ContainSingle("the fixture's language scenarios assume the installed store publishes exactly one language");

        await StashAsync<ProductProductTagMapping>(_ => true);
        await StashAsync<AclRecord>(acl => acl.EntityName == nameof(Product));
        await StashAsync<StoreMapping>(mapping => mapping.EntityName == nameof(Product));
        await _staticCacheManager.ClearAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDown()
    {
        foreach (var restore in Enumerable.Reverse(_restoreAfterFixture))
            await restore();
        _restoreAfterFixture.Clear();

        await _staticCacheManager.ClearAsync();
    }

    [TearDown]
    public async Task TearDown()
    {
        await _workContext.SetCurrentCustomerAsync(_originalCustomer);
        await _workContext.SetWorkingLanguageAsync(_originalLanguage);
        _originalCustomer.LanguageId = _originalCustomerLanguageId;
        await _customerService.UpdateCustomerAsync(_originalCustomer);

        foreach (var cleanup in Enumerable.Reverse(_cleanupAfterTest))
            await cleanup();
        _cleanupAfterTest.Clear();

        await RestoreCatalogSettingsAsync();
        await _staticCacheManager.ClearAsync();
    }

    [TestCaseSource(nameof(Scenarios))]
    public async Task ContractAnswersEveryFixtureCase(int scenarioIndex)
    {
        var scenario = _fixture.Value.Scenarios[scenarioIndex];
        var seeded = await SeedAsync(scenario.Dataset);

        await using var rust = _rustMode ? await RustService.StartAsync(await SnapshotDatabaseAsync()) : null;
        if (rust != null)
            await SaveRustFlagAsync(true, rust.BaseUri.ToString());

        var expectedBackend = _rustMode ? ProductTagReadBackend.Rust : ProductTagReadBackend.DotNet;

        using var scope = new AssertionScope();
        foreach (var fixtureCase in scenario.Cases)
        {
            var because = $"scenario '{scenario.Name}', case '{fixtureCase.Name}'";
            await DriveContextAsync(seeded, fixtureCase.Request);

            var result = await ReadAsync(fixtureCase.Request);

            result.Backend.Should().Be(expectedBackend, because);
            result.Items.Should().Equal(ExpectedItems(seeded, fixtureCase), because);

            if (rust == null)
                continue;

            var body = await rust.GetProductTagsAsync(WireQuery(seeded, fixtureCase.Request));
            JToken.DeepEquals(JArray.Parse(body), ExpectedJson(seeded, fixtureCase)).Should()
                .BeTrue($"the Rust body for {because} must equal the fixture, got {body}");
        }
    }

    [Test]
    public async Task ProductTagsRustIsOffWhenInstalledAndWhenTheSettingIsMissing()
    {
        _productTagsRustSettingExisted.Should().BeTrue("the installer saves every CatalogSettings property");
        _originalProductTagsRust.Should().BeFalse();

        await _settingService.DeleteSettingAsync(GetService<CatalogSettings>(), settings => settings.ProductTagsRust);
        await _settingService.ClearCacheAsync();

        (await _settingService.SettingExistsAsync(GetService<CatalogSettings>(), settings => settings.ProductTagsRust)).Should().BeFalse();
        GetService<CatalogSettings>().ProductTagsRust.Should().BeFalse();
    }

    [Test]
    public async Task UnreachableServiceFallsBackToDotNet()
    {
        var (seeded, fixtureCase) = await SeedFirstCaseAsync();
        await SaveRustFlagAsync(true, $"http://127.0.0.1:{UnusedPort()}/");

        var result = await ReadAsync(fixtureCase.Request);

        result.Backend.Should().Be(ProductTagReadBackend.DotNet);
        result.Items.Should().Equal(ExpectedItems(seeded, fixtureCase));
    }

    [Test]
    public async Task TurningTheFlagOffSendsTheNextReadToDotNet()
    {
        var (seeded, fixtureCase) = await SeedFirstCaseAsync();
        using var upstream = new StubUpstream(ExpectedJson(seeded, fixtureCase).ToString(Formatting.None));
        await SaveRustFlagAsync(true, upstream.BaseUri);

        var first = await ReadAsync(fixtureCase.Request);

        first.Backend.Should().Be(ProductTagReadBackend.Rust);
        first.Items.Should().Equal(ExpectedItems(seeded, fixtureCase));
        upstream.RequestedUrls.Should().Equal($"/api/catalog/product-tags?{WireQuery(seeded, fixtureCase.Request)}");

        await SaveRustFlagAsync(false, upstream.BaseUri);

        var next = await ReadAsync(fixtureCase.Request);

        next.Backend.Should().Be(ProductTagReadBackend.DotNet);
        next.Items.Should().Equal(ExpectedItems(seeded, fixtureCase));
        upstream.RequestedUrls.Should().HaveCount(1);
    }

    private async Task<(SeededScenario, FixtureCase)> SeedFirstCaseAsync()
    {
        var scenario = _fixture.Value.Scenarios[0];
        var seeded = await SeedAsync(scenario.Dataset);
        await DriveContextAsync(seeded, scenario.Cases[0].Request);

        return (seeded, scenario.Cases[0]);
    }

    private static async Task<ProductTagReadResult> ReadAsync(FixtureRequest request)
    {
        var previousCulture = CultureInfo.CurrentCulture;
        CultureInfo.CurrentCulture = request.Culture == string.Empty ? CultureInfo.InvariantCulture : new CultureInfo(request.Culture);
        try
        {
            return await GetService<IProductTagReadContract>().GetProductTagsAsync(request.Limit);
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
        }
    }

    private async Task DriveContextAsync(SeededScenario seeded, FixtureRequest request)
    {
        if (request.StoreId != 0)
            request.StoreId.Should().Be(seeded.CurrentStoreFixtureId, "a store-filtered case can only ask for the current store");

        var customer = await InsertAsync(new Customer
        {
            CustomerGuid = Guid.NewGuid(),
            Active = true,
            CreatedOnUtc = DateTime.UtcNow,
            LastActivityDateUtc = DateTime.UtcNow
        });
        foreach (var roleId in request.RoleIds)
            await InsertAsync(new CustomerCustomerRoleMapping { CustomerId = customer.Id, CustomerRoleId = seeded.RoleIds[roleId] });

        await _workContext.SetCurrentCustomerAsync(customer);
        await _workContext.SetWorkingLanguageAsync(await _languageService.GetLanguageByIdAsync(seeded.LanguageIds[request.LanguageId]));

        var catalogSettings = GetService<CatalogSettings>();
        catalogSettings.IgnoreAcl = request.IgnoreAcl;
        catalogSettings.IgnoreStoreLimitations = request.StoreId == 0;
        await _settingService.SaveSettingAsync(catalogSettings, settings => settings.IgnoreAcl, clearCache: false);
        await _settingService.SaveSettingAsync(catalogSettings, settings => settings.IgnoreStoreLimitations, clearCache: false);
        await _staticCacheManager.ClearAsync();

        (await _workContext.GetWorkingLanguageAsync()).Id.Should()
            .Be(seeded.LanguageIds[request.LanguageId], "the case's language must be selectable as the working language");
    }

    private async Task SaveRustFlagAsync(bool enabled, string serviceUrl)
    {
        var catalogSettings = GetService<CatalogSettings>();
        catalogSettings.ProductTagsRust = enabled;
        catalogSettings.CatalogReadsServiceUrl = serviceUrl;
        await _settingService.SaveSettingAsync(catalogSettings, settings => settings.ProductTagsRust, clearCache: false);
        await _settingService.SaveSettingAsync(catalogSettings, settings => settings.CatalogReadsServiceUrl, clearCache: false);
        await _settingService.ClearCacheAsync();
    }

    private async Task RestoreCatalogSettingsAsync()
    {
        var catalogSettings = GetService<CatalogSettings>();
        catalogSettings.IgnoreAcl = _originalIgnoreAcl;
        catalogSettings.IgnoreStoreLimitations = _originalIgnoreStoreLimitations;
        await _settingService.SaveSettingAsync(catalogSettings, settings => settings.IgnoreAcl, clearCache: false);
        await _settingService.SaveSettingAsync(catalogSettings, settings => settings.IgnoreStoreLimitations, clearCache: false);

        catalogSettings.ProductTagsRust = _originalProductTagsRust;
        catalogSettings.CatalogReadsServiceUrl = _originalServiceUrl;

        if (_productTagsRustSettingExisted)
            await _settingService.SaveSettingAsync(catalogSettings, settings => settings.ProductTagsRust, clearCache: false);
        else
            await _settingService.DeleteSettingAsync(catalogSettings, settings => settings.ProductTagsRust);

        if (_serviceUrlSettingExisted)
            await _settingService.SaveSettingAsync(catalogSettings, settings => settings.CatalogReadsServiceUrl, clearCache: false);
        else
            await _settingService.DeleteSettingAsync(catalogSettings, settings => settings.CatalogReadsServiceUrl);

        await _settingService.ClearCacheAsync();
    }

    private async Task<SeededScenario> SeedAsync(Dataset dataset)
    {
        var seeded = new SeededScenario();

        foreach (var store in dataset.Stores.OrderBy(store => store.Id))
        {
            if (store.Current)
            {
                seeded.CurrentStoreFixtureId = store.Id;
                seeded.StoreIds[store.Id] = _currentStore.Id;
                continue;
            }

            var inserted = await InsertAsync(new Store { Name = $"NOP-42 store {store.Id}", Url = $"http://nop42-store-{store.Id}.local/", DisplayOrder = 100 });
            seeded.StoreIds[store.Id] = inserted.Id;
        }

        foreach (var role in dataset.Roles)
        {
            var customerRole = await _customerService.GetCustomerRoleBySystemNameAsync(role.SystemName);
            customerRole.Should().NotBeNull($"the fixture role '{role.SystemName}' must exist in the installed store");
            seeded.RoleIds[role.Id] = customerRole.Id;
        }

        foreach (var language in dataset.Languages.OrderBy(language => language.Id))
        {
            if (language.Default)
            {
                language.Published.Should().BeTrue("the store's default language is published");
                seeded.LanguageIds[language.Id] = _originalLanguage.Id;
                continue;
            }

            var inserted = await InsertAsync(new Language
            {
                Name = language.Name,
                LanguageCulture = language.Culture,
                UniqueSeoCode = language.Culture[..2],
                Published = language.Published,
                DisplayOrder = 100
            });
            seeded.LanguageIds[language.Id] = inserted.Id;
        }

        foreach (var tag in dataset.Tags.OrderBy(tag => tag.Id))
        {
            var inserted = await InsertAsync(new ProductTag { Name = tag.Name });
            seeded.TagIds[tag.Id] = inserted.Id;
            await InsertAsync(new UrlRecord { EntityId = inserted.Id, EntityName = nameof(ProductTag), Slug = tag.SeName, IsActive = true, LanguageId = 0 });

            foreach (var localized in tag.Localized)
            {
                var languageId = seeded.LanguageIds[localized.LanguageId];
                if (localized.Name != null)
                {
                    await InsertAsync(new LocalizedProperty
                    {
                        EntityId = inserted.Id,
                        LanguageId = languageId,
                        LocaleKeyGroup = nameof(ProductTag),
                        LocaleKey = nameof(ProductTag.Name),
                        LocaleValue = localized.Name
                    });
                }

                if (localized.SeName != null)
                    await InsertAsync(new UrlRecord { EntityId = inserted.Id, EntityName = nameof(ProductTag), Slug = localized.SeName, IsActive = true, LanguageId = languageId });
            }
        }

        foreach (var product in dataset.Products.OrderBy(product => product.Id))
        {
            var inserted = await InsertAsync(new Product
            {
                Name = $"NOP-42 product {product.Id}",
                Published = product.Published,
                Deleted = product.Deleted,
                LimitedToStores = product.LimitedToStores,
                SubjectToAcl = product.SubjectToAcl,
                VisibleIndividually = true,
                CreatedOnUtc = DateTime.UtcNow,
                UpdatedOnUtc = DateTime.UtcNow
            });

            foreach (var storeId in product.LimitedToStoreIds)
                await InsertAsync(new StoreMapping { EntityId = inserted.Id, EntityName = nameof(Product), StoreId = seeded.StoreIds[storeId] });
            foreach (var roleId in product.AclRoleIds)
                await InsertAsync(new AclRecord { EntityId = inserted.Id, EntityName = nameof(Product), CustomerRoleId = seeded.RoleIds[roleId] });
            foreach (var tagId in product.TagIds)
                await InsertAsync(new ProductProductTagMapping { ProductId = inserted.Id, ProductTagId = seeded.TagIds[tagId] });
        }

        await _staticCacheManager.ClearAsync();

        return seeded;
    }

    private async Task<TEntity> InsertAsync<TEntity>(TEntity entity) where TEntity : BaseEntity
    {
        await GetService<IRepository<TEntity>>().InsertAsync(entity);
        //repositories only mark soft-deletable entities as deleted, cleanup removes the rows
        _cleanupAfterTest.Add(() => _dataProvider.DeleteEntityAsync(entity));

        return entity;
    }

    private async Task StashAsync<TEntity>(Expression<Func<TEntity, bool>> predicate) where TEntity : BaseEntity
    {
        var rows = _dataProvider.GetTable<TEntity>().Where(predicate).ToList();
        if (rows.Count == 0)
            return;

        await _dataProvider.BulkDeleteEntitiesAsync(predicate);
        _restoreAfterFixture.Add(() => _dataProvider.BulkInsertEntitiesAsync(rows));
    }

    private string WireQuery(SeededScenario seeded, FixtureRequest request)
    {
        var storeId = request.StoreId == 0 ? 0 : _currentStore.Id;
        var roleIds = string.Join(",", request.RoleIds.Select(roleId => seeded.RoleIds[roleId]));

        return $"storeId={storeId}&roleIds={roleIds}&ignoreAcl={(request.IgnoreAcl ? "true" : "false")}" +
            $"&languageId={seeded.LanguageIds[request.LanguageId]}&culture={request.Culture}&limit={request.Limit}";
    }

    private static List<ProductTagReadItem> ExpectedItems(SeededScenario seeded, FixtureCase fixtureCase) =>
        fixtureCase.Expected
            .Select(item => new ProductTagReadItem(seeded.TagIds[(int)item["id"]], (string)item["name"], (string)item["seName"], (int)item["productCount"]))
            .ToList();

    private static JArray ExpectedJson(SeededScenario seeded, FixtureCase fixtureCase)
    {
        var expected = (JArray)fixtureCase.Expected.DeepClone();
        foreach (var item in expected)
            item["id"] = seeded.TagIds[(int)item["id"]];

        return expected;
    }

    private static int UnusedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        return port;
    }

    private static async Task<string> SnapshotDatabaseAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nop42-product-tags-{Guid.NewGuid():N}.sqlite");

        await using var connection = new SqliteConnection(NopTestConfiguration.SqliteConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        //a plain path target inherits the in-memory open flags and writes nothing, the URI form writes a file
        command.CommandText = "VACUUM INTO $target";
        command.Parameters.AddWithValue("$target", $"{new Uri(path).AbsoluteUri}?mode=rwc");
        await command.ExecuteNonQueryAsync();

        new FileInfo(path).Length.Should().BePositive("the snapshot the Rust service reads must contain the seeded database");

        return path;
    }

    private sealed class SeededScenario
    {
        public int CurrentStoreFixtureId { get; set; }
        public Dictionary<int, int> StoreIds { get; } = new();
        public Dictionary<int, int> RoleIds { get; } = new();
        public Dictionary<int, int> LanguageIds { get; } = new();
        public Dictionary<int, int> TagIds { get; } = new();
    }

    private sealed class RustService : IAsyncDisposable
    {
        private const string LISTENING_PREFIX = "catalog-reads listening on ";
        private static readonly HttpClient _httpClient = new();

        private readonly Process _process;
        private readonly ConcurrentQueue<string> _output;
        private readonly string _databasePath;

        private RustService(Process process, ConcurrentQueue<string> output, string databasePath, Uri baseUri)
        {
            _process = process;
            _output = output;
            _databasePath = databasePath;
            BaseUri = baseUri;
        }

        public Uri BaseUri { get; }

        public static async Task<RustService> StartAsync(string databasePath)
        {
            var binaryPath = Environment.GetEnvironmentVariable("CATALOG_READS_BIN");
            if (string.IsNullOrEmpty(binaryPath))
            {
                var directory = new DirectoryInfo(AppContext.BaseDirectory);
                while (directory != null && !Directory.Exists(Path.Combine(directory.FullName, "rust", "catalog-reads")))
                    directory = directory.Parent;
                var binaryName = OperatingSystem.IsWindows() ? "catalog-reads.exe" : "catalog-reads";
                binaryPath = Path.Combine(directory?.FullName ?? string.Empty, "rust", "catalog-reads", "target", "debug", binaryName);
            }

            if (!File.Exists(binaryPath))
            {
                File.Delete(databasePath);
                Assert.Fail($"PRODUCT_TAGS_RUST=on needs the catalog-reads binary at '{binaryPath}'. Build it with `{BUILD_COMMAND}` or set CATALOG_READS_BIN.");
            }

            var startInfo = new ProcessStartInfo(binaryPath)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            startInfo.Environment["CATALOG_READS_DATABASE_URL"] = $"sqlite://{databasePath}?mode=ro";
            startInfo.Environment["CATALOG_READS_LISTEN"] = "127.0.0.1:0";

            var output = new ConcurrentQueue<string>();
            var listening = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
            var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            process.OutputDataReceived += (_, args) =>
            {
                if (args.Data == null)
                    return;

                output.Enqueue(args.Data);
                if (args.Data.StartsWith(LISTENING_PREFIX, StringComparison.Ordinal))
                    listening.TrySetResult(new Uri($"http://{args.Data[LISTENING_PREFIX.Length..].Trim()}/"));
            };
            process.ErrorDataReceived += (_, args) =>
            {
                if (args.Data != null)
                    output.Enqueue($"stderr: {args.Data}");
            };
            process.Exited += (_, _) => listening.TrySetException(new InvalidOperationException($"catalog-reads exited with code {process.ExitCode}"));

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            try
            {
                return new RustService(process, output, databasePath, await listening.Task.WaitAsync(TimeSpan.FromSeconds(30)));
            }
            catch
            {
                await new RustService(process, output, databasePath, null).DisposeAsync();
                throw;
            }
        }

        public Task<string> GetProductTagsAsync(string query) =>
            _httpClient.GetStringAsync(new Uri(BaseUri, $"/api/catalog/product-tags?{query}"));

        public async ValueTask DisposeAsync()
        {
            if (!_process.HasExited)
                _process.Kill(entireProcessTree: true);
            await _process.WaitForExitAsync();
            _process.Dispose();
            File.Delete(_databasePath);

            foreach (var line in _output)
                await TestContext.Out.WriteLineAsync($"[catalog-reads] {line}");
        }
    }

    private sealed class StubUpstream : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly string _body;
        private readonly ConcurrentQueue<string> _requestedUrls = new();

        public StubUpstream(string body)
        {
            _body = body;
            //Windows lets a non-elevated process listen on localhost only
            BaseUri = $"http://localhost:{UnusedPort()}/";
            _listener.Prefixes.Add(BaseUri);
            _listener.Start();
            _ = ServeAsync();
        }

        public string BaseUri { get; }

        public IReadOnlyCollection<string> RequestedUrls => _requestedUrls;

        private async Task ServeAsync()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync();
                }
                catch (Exception) when (!_listener.IsListening)
                {
                    return;
                }

                _requestedUrls.Enqueue(context.Request.RawUrl);
                var bytes = Encoding.UTF8.GetBytes(_body);
                context.Response.ContentType = "application/json";
                await context.Response.OutputStream.WriteAsync(bytes);
                context.Response.Close();
            }
        }

        public void Dispose() => _listener.Close();
    }

    private sealed record FixtureFile(IList<Scenario> Scenarios);

    private sealed record Scenario(string Name, Dataset Dataset, IList<FixtureCase> Cases);

    private sealed record Dataset(IList<FixtureStore> Stores, IList<FixtureRole> Roles, IList<FixtureLanguage> Languages, IList<FixtureTag> Tags, IList<FixtureProduct> Products);

    private sealed record FixtureStore(int Id, bool Current);

    private sealed record FixtureRole(int Id, string SystemName);

    private sealed record FixtureLanguage(int Id, string Name, string Culture, bool Default, bool Published);

    private sealed record FixtureTag(int Id, string Name, string SeName, IList<FixtureLocalizedTag> Localized);

    private sealed record FixtureLocalizedTag(int LanguageId, string Name, string SeName);

    private sealed record FixtureProduct(int Id, bool Published, bool Deleted, bool LimitedToStores, IList<int> LimitedToStoreIds, bool SubjectToAcl, IList<int> AclRoleIds, IList<int> TagIds);

    private sealed record FixtureCase(string Name, FixtureRequest Request, JArray Expected);

    private sealed record FixtureRequest(int StoreId, IList<int> RoleIds, bool IgnoreAcl, int LanguageId, string Culture, int Limit);
}