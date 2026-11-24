import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401

import post_slack
from vulnscan.model import Finding
from vulnscan.report import build_results, write_json
from vulnscan.slack import REMEDIATE_LINE, build_payload, escape, format_text, post, validate_webhook

# Assembled at runtime so secret scanners do not treat the fixture as a leaked webhook.
FAKE_WEBHOOK = "https://hooks.slack.com/" + "/".join(["services", "TFAKE", "BFAKE", "notarealsecretvalue"])


def make_finding(**overrides):
    data = dict(
        id="VS-abc123",
        title="Newtonsoft.Json 12.0.3 is affected by GHSA-5crp-9r3c-p9vr",
        severity="high",
        file="tools/vuln-scan/sample/VulnDemo/VulnDemo.csproj",
        line=13,
        rule="dependency/vulnerable-package",
        fix_hint="Bump Newtonsoft.Json from 12.0.3 to 13.0.1 in VulnDemo.csproj.",
        category="dependency",
        why="Newtonsoft.Json 12.0.3 has a published advisory.",
    )
    data.update(overrides)
    return Finding(**data)


class FormatterTests(unittest.TestCase):
    def test_message_layout(self):
        lines = format_text(make_finding()).splitlines()
        self.assertEqual(lines[0], ":red_circle: *HIGH*: Newtonsoft.Json 12.0.3 is affected by GHSA-5crp-9r3c-p9vr")
        self.assertEqual(lines[1], "`tools/vuln-scan/sample/VulnDemo/VulnDemo.csproj:13`")
        self.assertEqual(lines[2], "Why it matters: Newtonsoft.Json 12.0.3 has a published advisory.")
        self.assertTrue(lines[3].startswith("Fix hint: Bump Newtonsoft.Json"))
        self.assertEqual(lines[-1], REMEDIATE_LINE)

    def test_machine_readable_block_round_trips(self):
        text = format_text(make_finding(fix_hint='Use <PackageReference Include="X" /> & rebuild'))
        block = text.split("```")[1]
        unescaped = block.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        data = json.loads(unescaped)
        self.assertEqual(data["id"], "VS-abc123")
        self.assertEqual(data["line"], 13)
        self.assertEqual(data["fix_hint"], 'Use <PackageReference Include="X" /> & rebuild')

    def test_escapes_slack_control_characters(self):
        self.assertEqual(escape("<a & b>"), "&lt;a &amp; b&gt;")
        text = format_text(make_finding(title="<!channel> ping"))
        self.assertNotIn("<!channel>", text)

    def test_why_falls_back_to_message_then_title(self):
        f = make_finding(why="", details={"message": "from semgrep"})
        self.assertIn("Why it matters: from semgrep", format_text(f))
        f = make_finding(why="", details={})
        self.assertIn(f"Why it matters: {f.title}", format_text(f))

    def test_severity_emoji(self):
        self.assertTrue(format_text(make_finding(severity="critical")).startswith(":rotating_light: *CRITICAL*"))

    def test_payload_channel_and_no_unfurl(self):
        payload = build_payload(make_finding(), "#security-findings")
        self.assertEqual(payload["channel"], "#security-findings")
        self.assertFalse(payload["unfurl_links"])
        self.assertNotIn("channel", build_payload(make_finding(), None))


class WebhookTests(unittest.TestCase):
    def test_rejects_missing_or_foreign_webhooks(self):
        with self.assertRaises(ValueError):
            validate_webhook(None)
        with self.assertRaises(ValueError):
            validate_webhook("http://hooks.slack.com/services/x")
        with self.assertRaises(ValueError):
            validate_webhook("https://example.com/hooks.slack.com/services/x")
        self.assertEqual(validate_webhook(FAKE_WEBHOOK), FAKE_WEBHOOK)

    def test_errors_do_not_leak_webhook(self):
        import urllib.error

        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
            with self.assertRaises(RuntimeError) as ctx:
                post({"text": "x"}, FAKE_WEBHOOK)
        self.assertNotIn("notarealsecretvalue", str(ctx.exception))


class PostSlackCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.results = Path(self._tmp.name) / "scan-results.json"
        findings = [make_finding(id="VS-low", severity="low"), make_finding(id="VS-crit", severity="critical")]
        write_json(build_results(findings, {}), self.results)

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *args, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=True), redirect_stdout(out), redirect_stderr(err):
            code = post_slack.main([str(self.results), *args])
        return code, out.getvalue(), err.getvalue()

    def test_dry_run_previews_top_finding_without_posting(self):
        with mock.patch("post_slack.post") as fake_post:
            code, out, _ = self.run_cli("--dry-run", env={"SLACK_CHANNEL": "#sec", "SLACK_WEBHOOK_URL": FAKE_WEBHOOK})
        self.assertEqual(code, 0)
        fake_post.assert_not_called()
        self.assertIn("VS-crit", out)
        self.assertNotIn("notarealsecretvalue", out)

    def test_posts_with_env_and_never_prints_webhook(self):
        with mock.patch("post_slack.post") as fake_post:
            code, out, err = self.run_cli(env={"SLACK_CHANNEL": "#sec", "SLACK_WEBHOOK_URL": FAKE_WEBHOOK})
        self.assertEqual(code, 0)
        payload, url = fake_post.call_args[0]
        self.assertEqual(url, FAKE_WEBHOOK)
        self.assertEqual(payload["channel"], "#sec")
        self.assertNotIn("notarealsecretvalue", out + err)

    def test_requires_channel(self):
        code, _, err = self.run_cli(env={"SLACK_WEBHOOK_URL": FAKE_WEBHOOK})
        self.assertEqual(code, 2)
        self.assertIn("SLACK_CHANNEL", err)

    def test_min_severity_filters(self):
        write_json(build_results([make_finding(severity="low")], {}), self.results)
        with mock.patch("post_slack.post") as fake_post:
            code, out, _ = self.run_cli("--min-severity", "high", env={"SLACK_CHANNEL": "#sec", "SLACK_WEBHOOK_URL": FAKE_WEBHOOK})
        self.assertEqual(code, 0)
        fake_post.assert_not_called()
        self.assertIn("nothing to post", out)


if __name__ == "__main__":
    unittest.main()
