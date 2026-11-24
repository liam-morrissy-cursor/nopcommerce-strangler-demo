import json
import tempfile
import unittest
from pathlib import Path

from helpers import CORE_CSPROJ, FIXTURES, WEB_CSPROJ, write

from vulnscan.advisories import advisory_id_from_url, pick_patched_version, version_in_range
from vulnscan.deps import hits_to_findings, parse_vulnerable_report

FIXED = {
    "GHSA-rxg9-xrhp-64gj": "4.7.2",
    "GHSA-5crp-9r3c-p9vr": "13.0.1",
    "GHSA-gwg2-r3hj-4w44": "3.1.13",
    "GHSA-v76p-62qx-wwq2": "3.2.0",
}


class FakeResolver:
    def resolve(self, ghsa_id, package, installed):
        return {"fixed_version": FIXED.get(ghsa_id), "summary": None, "cve_id": None}


class DotnetReportParserTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        write(self.root, "src/Core/Core.csproj", CORE_CSPROJ)
        write(self.root, "src/Web/Web.csproj", WEB_CSPROJ)
        raw = (FIXTURES / "dotnet-list-vulnerable.json").read_text().replace("{ROOT}", self.root.as_posix())
        self.report = json.loads(raw)

    def tearDown(self):
        self._tmp.cleanup()

    def test_flattens_and_merges_frameworks(self):
        hits = parse_vulnerable_report(self.report)
        self.assertEqual(len(hits), 5)
        newtonsoft = [h for h in hits if h.package == "Newtonsoft.Json"]
        self.assertEqual(len(newtonsoft), 1)
        self.assertEqual(newtonsoft[0].frameworks, ["net10.0", "net9.0"])
        self.assertFalse(newtonsoft[0].transitive)
        self.assertEqual(newtonsoft[0].severity, "high")
        moderate = [h for h in hits if "gwg2" in h.advisory_url][0]
        self.assertEqual(moderate.severity, "medium")

    def test_project_without_frameworks_is_ignored(self):
        self.assertEqual(parse_vulnerable_report({"projects": [{"path": "x.csproj"}]}), [])
        self.assertEqual(parse_vulnerable_report({}), [])

    def test_direct_dependency_points_at_package_reference(self):
        findings = {f.details["package"]: f for f in hits_to_findings(parse_vulnerable_report(self.report), self.root, FakeResolver())}
        f = findings["Newtonsoft.Json"]
        self.assertEqual((f.file, f.line, f.severity), ("src/Web/Web.csproj", 3, "high"))
        self.assertEqual(f.details["fixed_version"], "13.0.1")
        self.assertEqual(f.details["advisories"][0]["id"], "GHSA-5crp-9r3c-p9vr")
        self.assertIn("Bump Newtonsoft.Json from 12.0.3 to 13.0.1", f.fix_hint)
        self.assertEqual(f.rule, "dependency/vulnerable-package")

    def test_transitive_dependency_groups_projects_and_picks_lowest(self):
        findings = {f.details["package"]: f for f in hits_to_findings(parse_vulnerable_report(self.report), self.root, FakeResolver())}
        f = findings["System.Drawing.Common"]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.file, "src/Core/Core.csproj")
        self.assertTrue(f.details["transitive"])
        self.assertEqual(sorted(f.details["affected_projects"]), ["src/Core/Core.csproj", "src/Web/Web.csproj"])
        self.assertIn('Version="4.7.2"', f.fix_hint)

    def test_multiple_advisories_take_highest_severity_and_fix(self):
        findings = {f.details["package"]: f for f in hits_to_findings(parse_vulnerable_report(self.report), self.root, FakeResolver())}
        f = findings["SixLabors.ImageSharp"]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.details["fixed_version"], "3.2.0")
        self.assertIn("2 advisories (1 high, 1 medium)", f.title)
        self.assertEqual([a["id"] for a in f.details["advisories"]], ["GHSA-v76p-62qx-wwq2", "GHSA-gwg2-r3hj-4w44"])

    def test_why_uses_advisory_summary_when_available(self):
        class SummaryResolver(FakeResolver):
            def resolve(self, ghsa_id, package, installed):
                return {**super().resolve(ghsa_id, package, installed), "summary": "Remote code execution."}

        findings = {f.details["package"]: f for f in hits_to_findings(parse_vulnerable_report(self.report), self.root, SummaryResolver())}
        self.assertEqual(
            findings["System.Drawing.Common"].why,
            "Remote code execution (GHSA-rxg9-xrhp-64gj) in System.Drawing.Common 4.7.0, shipped by 2 project(s).",
        )

    def test_ids_are_stable(self):
        a = hits_to_findings(parse_vulnerable_report(self.report), self.root, FakeResolver())
        b = hits_to_findings(parse_vulnerable_report(self.report), self.root, FakeResolver())
        self.assertEqual([f.id for f in a], [f.id for f in b])
        self.assertEqual(len({f.id for f in a}), len(a))


class AdvisoryTests(unittest.TestCase):
    def test_advisory_id_from_url(self):
        self.assertEqual(advisory_id_from_url("https://github.com/advisories/GHSA-5crp-9r3c-p9vr"), "GHSA-5crp-9r3c-p9vr")

    def test_version_ranges(self):
        self.assertTrue(version_in_range("12.0.3", "< 13.0.1"))
        self.assertFalse(version_in_range("13.0.1", "< 13.0.1"))
        self.assertTrue(version_in_range("5.0.0", ">= 5.0.0, < 5.0.3"))
        self.assertFalse(version_in_range("4.7.0", ">= 5.0.0, < 5.0.3"))

    def test_pick_patched_version_uses_matching_range(self):
        vulns = [
            {"package": {"ecosystem": "nuget", "name": "System.Drawing.Common"}, "vulnerable_version_range": ">= 5.0.0, < 5.0.3", "first_patched_version": "5.0.3"},
            {"package": {"ecosystem": "nuget", "name": "System.Drawing.Common"}, "vulnerable_version_range": "< 4.7.2", "first_patched_version": "4.7.2"},
            {"package": {"ecosystem": "npm", "name": "other"}, "vulnerable_version_range": "< 9", "first_patched_version": "9.0.0"},
        ]
        self.assertEqual(pick_patched_version(vulns, "system.drawing.common", "4.7.0"), "4.7.2")
        self.assertEqual(pick_patched_version(vulns, "System.Drawing.Common", "5.0.1"), "5.0.3")
        self.assertIsNone(pick_patched_version([], "x", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
