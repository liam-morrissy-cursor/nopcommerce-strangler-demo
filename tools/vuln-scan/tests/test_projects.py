import json
import tempfile
import unittest
from pathlib import Path

from helpers import CORE_CSPROJ, WEB_CSPROJ, write

from vulnscan.projects import (
    discover_projects,
    introduced_by,
    load_project,
    lowest_projects,
    parse_package_file,
    scan_targets,
    solution_projects,
)


class ProjectParserTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.core = write(self.root, "src/Core/Core.csproj", CORE_CSPROJ)
        self.web = write(self.root, "src/Web/Web.csproj", WEB_CSPROJ)

    def tearDown(self):
        self._tmp.cleanup()

    def test_package_reference_attribute_and_child_version(self):
        packages = parse_package_file(self.web)
        self.assertEqual(packages["newtonsoft.json"].version, "12.0.3")
        self.assertEqual(packages["newtonsoft.json"].line, 3)
        self.assertEqual(packages["imagetools"].version, "2.0.0")
        self.assertEqual(packages["imagetools"].line, 4)

    def test_central_package_management(self):
        write(
            self.root,
            "Directory.Packages.props",
            "<Project>\n  <ItemGroup>\n    <PackageVersion Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\n  </ItemGroup>\n</Project>\n",
        )
        cpm = write(
            self.root,
            "src/Cpm/Cpm.csproj",
            '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n    <PackageReference Include="Newtonsoft.Json" />\n  </ItemGroup>\n</Project>\n',
        )
        ref = load_project(cpm, self.root).locate("NEWTONSOFT.JSON")
        self.assertEqual(ref.file.name, "Directory.Packages.props")
        self.assertEqual((ref.version, ref.line), ("13.0.3", 3))

    def test_explicit_version_wins_over_central(self):
        write(self.root, "Directory.Packages.props", '<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>')
        ref = load_project(self.web, self.root).locate("Newtonsoft.Json")
        self.assertEqual(ref.file, self.web)

    def test_solution_and_stray_projects(self):
        sln = write(
            self.root,
            "src/All.sln",
            'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Web", "Web\\Web.csproj", "{1}"\nEndProject\n',
        )
        self.assertEqual(solution_projects(sln), [self.web])
        targets = scan_targets(self.root, [sln])
        self.assertEqual(targets, [sln, self.core])

    def test_discover_skips_bin_obj_and_excludes(self):
        write(self.root, "src/Web/obj/Generated.csproj", CORE_CSPROJ)
        write(self.root, "tools/fixtures/Fake.csproj", CORE_CSPROJ)
        found = discover_projects(self.root, exclude=["tools/fixtures"])
        self.assertEqual(found, [self.core, self.web])

    def test_lowest_projects_follows_project_references(self):
        self.assertEqual(lowest_projects([self.web, self.core]), [self.core])
        self.assertEqual(lowest_projects([self.web]), [self.web])

    def test_introduced_by_reads_restore_assets(self):
        assets = {
            "targets": {
                "net10.0": {
                    "PdfRpt.Core/1.5.18": {"dependencies": {"System.Drawing.Common": "4.7.0"}},
                    "System.Drawing.Common/4.7.0": {},
                    "Humanizer/3.0.0": {},
                }
            },
            "project": {"frameworks": {"net10.0": {"dependencies": {"PdfRpt.Core": {}, "Humanizer": {}}}}},
        }
        write(self.root, "src/Core/obj/project.assets.json", json.dumps(assets))
        self.assertEqual(introduced_by(self.core, "System.Drawing.Common"), ["PdfRpt.Core"])
        self.assertEqual(introduced_by(self.web, "System.Drawing.Common"), [])


if __name__ == "__main__":
    unittest.main()
