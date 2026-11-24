import unittest

import helpers  # noqa: F401

from vulnscan.antiforgery import find_unprotected_actions
from vulnscan.gate import blocking
from vulnscan.model import Finding, sort_findings
from vulnscan.report import build_results, render_markdown

BASE = """
[AutoValidateAntiforgeryToken]
public abstract partial class BaseAdminController : BaseController
{
}
"""
BASE_CONTROLLER = "public abstract partial class BaseController : Controller\n{\n}\n"


def controller(name, base, body, attrs=""):
    return f"{attrs}\npublic partial class {name} : {base}\n{{\n{body}\n}}\n"


POST_ACTION = "    [HttpPost]\n    public virtual async Task<IActionResult> Save(Model model)\n    {\n    }\n"


class AntiforgeryTests(unittest.TestCase):
    def actions(self, **files):
        sources = {"Base.cs": BASE, "BaseController.cs": BASE_CONTROLLER, **files}
        return [(a.controller, a.method, a.line) for a in find_unprotected_actions(sources)]

    def test_flags_post_without_token(self):
        self.assertEqual(self.actions(**{"A.cs": controller("ShopController", "BaseController", POST_ACTION)}), [("ShopController", "Save", 5)])

    def test_inherited_attribute_protects(self):
        self.assertEqual(self.actions(**{"A.cs": controller("ProductController", "BaseAdminController", POST_ACTION)}), [])

    def test_multi_level_inheritance_across_files(self):
        files = {
            "Tax.cs": controller("TaxController", "BaseAdminController", ""),
            "Avalara.cs": controller("AvalaraTaxController", "TaxController", POST_ACTION),
        }
        self.assertEqual(self.actions(**files), [])

    def test_class_and_method_attributes(self):
        self.assertEqual(self.actions(**{"A.cs": controller("ShopController", "BaseController", POST_ACTION, "[AutoValidateAntiforgeryToken]")}), [])
        body = "    [HttpPost, ValidateAntiForgeryToken]\n    public IActionResult Save() { }\n"
        self.assertEqual(self.actions(**{"A.cs": controller("ShopController", "BaseController", body)}), [])

    def test_explicit_ignore_and_api_controllers_are_skipped(self):
        body = "    [HttpPost]\n    [IgnoreAntiforgeryToken]\n    public IActionResult Hook() { }\n"
        self.assertEqual(self.actions(**{"A.cs": controller("ShopController", "BaseController", body)}), [])
        self.assertEqual(self.actions(**{"A.cs": controller("OrdersController", "ControllerBase", POST_ACTION, "[ApiController]")}), [])

    def test_webhook_controllers_and_get_actions_are_skipped(self):
        self.assertEqual(self.actions(**{"A.cs": controller("PayPalWebhookController", "Controller", POST_ACTION)}), [])
        body = "    [HttpGet]\n    public IActionResult List() { }\n"
        self.assertEqual(self.actions(**{"A.cs": controller("ShopController", "BaseController", body)}), [])

    def test_commented_attributes_do_not_count(self):
        body = "    //[HttpPost]\n    public IActionResult Save() { }\n    /*\n    [HttpPost]\n    */\n    public IActionResult Other() { }\n"
        self.assertEqual(self.actions(**{"A.cs": controller("ShopController", "BaseController", body)}), [])

    def test_global_filter_disables_check(self):
        startup = "services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));"
        self.assertEqual(self.actions(**{"A.cs": controller("ShopController", "BaseController", POST_ACTION), "Startup.cs": startup}), [])


def f(sev, category="code", file="a.cs", line=1):
    return Finding(id=f"{sev}{file}{line}", title=sev, severity=sev, file=file, line=line, rule="r", fix_hint="", category=category)


class ReportAndGateTests(unittest.TestCase):
    def test_sort_and_gate(self):
        findings = [f("medium"), f("critical", file="b.cs"), f("high", category="dependency"), f("high")]
        ordered = sort_findings(findings)
        self.assertEqual([(x.severity, x.category) for x in ordered][:3], [("critical", "code"), ("high", "dependency"), ("high", "code")])
        self.assertEqual(len(blocking(findings, "high")), 3)
        self.assertEqual(blocking(findings, "none"), [])

    def test_results_and_markdown(self):
        results = build_results([f("low"), f("high")], {"scanned_at": "now", "commit": "abc", "errors": ["oops"]})
        self.assertEqual(results["summary"]["by_severity"]["high"], 1)
        self.assertEqual(results["findings"][0]["severity"], "high")
        for key in ("id", "title", "severity", "file", "line", "rule", "fix_hint"):
            self.assertIn(key, results["findings"][0])
        md = render_markdown(results)
        self.assertIn("| 1 | **high** |", md)
        self.assertIn("## Scanner errors", md)


if __name__ == "__main__":
    unittest.main()
