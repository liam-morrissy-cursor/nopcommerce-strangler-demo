using System.Reflection;
using System.Text.Json;
using AwesomeAssertions;
using NUnit.Framework;

namespace Nop.Tests.Nop.Services.Tests.Security;

/// <summary>
/// Guards against reintroducing vulnerable transitive dependencies of Nop.Services
/// </summary>
[TestFixture]
public class DependencySecurityTests
{
    private const string SYSTEM_DRAWING_COMMON = "System.Drawing.Common";

    //CVE-2021-24112 (GHSA-rxg9-xrhp-64gj) affects versions below 4.7.2.
    //The 4.7.2 package ships assembly version 4.0.0.2, while 4.7.0 ships 4.0.0.1.
    private static readonly Version _minPackageVersion = new(4, 7, 2);
    private static readonly Version _minAssemblyVersion = new(4, 0, 0, 2);

    [Test]
    public void SystemDrawingCommonResolvedPackageIsPatched()
    {
        var depsFile = Path.Combine(AppContext.BaseDirectory, $"{typeof(DependencySecurityTests).Assembly.GetName().Name}.deps.json");
        File.Exists(depsFile).Should().BeTrue($"'{depsFile}' is required to inspect resolved package versions");

        using var document = JsonDocument.Parse(File.ReadAllText(depsFile));

        var versions = document.RootElement
            .GetProperty("libraries")
            .EnumerateObject()
            .Select(library => library.Name.Split('/'))
            .Where(parts => parts.Length == 2 && parts[0].Equals(SYSTEM_DRAWING_COMMON, StringComparison.OrdinalIgnoreCase))
            .Select(parts => Version.Parse(parts[1].Split('-')[0]))
            .ToList();

        versions.Should().NotBeEmpty();
        versions.Should().OnlyContain(version => version >= _minPackageVersion,
            $"{SYSTEM_DRAWING_COMMON} below {_minPackageVersion} is affected by CVE-2021-24112");
    }

    [Test]
    public void SystemDrawingCommonLoadedAssemblyIsPatched()
    {
        var assemblyName = Assembly.Load(SYSTEM_DRAWING_COMMON).GetName();

        assemblyName.Name.Should().Be(SYSTEM_DRAWING_COMMON);
        assemblyName.Version.Should().BeGreaterThanOrEqualTo(_minAssemblyVersion,
            $"{SYSTEM_DRAWING_COMMON} below 4.7.2 is affected by CVE-2021-24112");
    }
}
