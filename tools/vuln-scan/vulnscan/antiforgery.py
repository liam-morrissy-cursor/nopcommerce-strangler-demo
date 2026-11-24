"""Missing antiforgery validation on state-changing MVC actions.

Semgrep sees one file at a time, but nopCommerce applies [AutoValidateAntiforgeryToken] on
base controllers (e.g. BaseAdminController), so this check indexes every controller class
across the scanned tree and resolves inheritance before deciding an action is unprotected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .model import Finding, finding_id

RULE = "code/missing-antiforgery-token"
TITLE = "State-changing action without antiforgery validation"
WHY = "A POST action that skips antiforgery validation can be triggered from another site using the victim's signed-in session (CSRF)."
FIX = (
    "Add [ValidateAntiForgeryToken] to the action, or [AutoValidateAntiforgeryToken] to the controller "
    "(or inherit from a base controller that has it). If the endpoint is called server-to-server, mark it "
    "[IgnoreAntiforgeryToken] and authenticate the caller another way (signature, API key)."
)

_VERB_ATTR = re.compile(r"\bHttp(Post|Put|Patch|Delete)\b")
_VALIDATE = re.compile(r"\b(Auto)?ValidateAntiforgeryToken\b", re.IGNORECASE)
_IGNORE = re.compile(r"\bIgnoreAntiforgeryToken\b", re.IGNORECASE)
_API_CONTROLLER = re.compile(r"\bApiController\b")
_CLASS = re.compile(r"\bclass\s+(\w+)(?:<[^>]*>)?(?:\s*\([^)]*\))?\s*(?::\s*([\w.]+))?")
_METHOD = re.compile(r"^\s*(public|internal|protected)\b[^=;(]*?\b(\w+)\s*\(")
_GLOBAL_FILTER = re.compile(r"Filters\.Add\w*\s*[(<][^;]*AutoValidateAntiforgeryToken", re.IGNORECASE)
_FRAMEWORK_BASES = {"Controller", "ControllerBase"}
# Server-to-server callbacks (payment/tax/email providers) authenticate by signature, not cookies.
_SERVER_TO_SERVER = re.compile(r"Webhook\w*Controller$")


@dataclass
class ControllerClass:
    name: str
    base: str | None
    attributes: list[str] = field(default_factory=list)


@dataclass
class Action:
    controller: str
    method: str
    attributes: list[str]
    file: Path
    line: int


def _short(type_name: str | None) -> str | None:
    return type_name.rsplit(".", 1)[-1] if type_name else None


def parse_csharp(path: Path, text: str) -> tuple[list[ControllerClass], list[Action]]:
    classes: list[ControllerClass] = []
    actions: list[Action] = []
    pending: list[str] = []
    current: str | None = None
    in_block_comment = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if in_block_comment:
            if "*/" in line:
                in_block_comment = False
            continue
        if line.startswith("/*"):
            in_block_comment = "*/" not in line
            continue
        if not line or line.startswith("//"):
            continue
        if line.startswith("[") and not line.startswith("[]"):
            pending.append(line)
            continue
        class_match = _CLASS.search(line)
        if class_match and not line.startswith(("return", "var ", "new ")):
            current = class_match.group(1)
            classes.append(ControllerClass(current, _short(class_match.group(2)), pending))
        else:
            method_match = _METHOD.match(raw)
            if method_match and current and any(_VERB_ATTR.search(a) for a in pending):
                actions.append(Action(current, method_match.group(2), pending, path, number))
        pending = []
    return classes, actions


def _iter_cs_files(repo_root: Path, paths: list[str], exclude: list[str]):
    exclude = [e.strip("/") for e in exclude]
    for base in paths:
        for path in sorted((repo_root / base).rglob("*.cs")):
            rel = path.relative_to(repo_root).as_posix()
            if any(part in ("bin", "obj") for part in path.parts):
                continue
            if any(rel == e or rel.startswith(e + "/") for e in exclude):
                continue
            yield path, rel


def find_unprotected_actions(sources: dict[str, str]) -> list[Action]:
    """`sources` maps repo-relative path to file content. Pure function for testing."""
    index: dict[str, ControllerClass] = {}
    actions: list[Action] = []
    for rel, text in sources.items():
        if _GLOBAL_FILTER.search(text):
            return []
        classes, file_actions = parse_csharp(Path(rel), text)
        for cls in classes:
            existing = index.get(cls.name)
            if existing:
                existing.attributes += cls.attributes
                existing.base = existing.base or cls.base
            else:
                index[cls.name] = cls
        actions.extend(file_actions)

    def chain(name: str):
        seen = set()
        while name and name in index and name not in seen:
            seen.add(name)
            yield index[name]
            name = index[name].base

    def is_controller(name: str) -> bool:
        if name.endswith("Controller"):
            return True
        return any(c.base in _FRAMEWORK_BASES for c in chain(name))

    unprotected = []
    for action in actions:
        if not is_controller(action.controller) or _SERVER_TO_SERVER.search(action.controller):
            continue
        attrs = " ".join(action.attributes)
        if _VALIDATE.search(attrs) or _IGNORE.search(attrs):
            continue
        class_attrs = " ".join(a for c in chain(action.controller) for a in c.attributes)
        if _VALIDATE.search(class_attrs) or _IGNORE.search(class_attrs) or _API_CONTROLLER.search(class_attrs):
            continue
        unprotected.append(action)
    return unprotected


def run_antiforgery_check(repo_root: Path, paths: list[str], exclude: list[str]) -> list[Finding]:
    sources = {rel: path.read_text(encoding="utf-8-sig", errors="replace") for path, rel in _iter_cs_files(repo_root, paths, exclude)}
    findings = []
    for action in find_unprotected_actions(sources):
        file = action.file.as_posix()
        findings.append(
            Finding(
                id=finding_id("code", RULE, file, action.controller, action.method),
                title=f"{TITLE}: {action.controller}.{action.method}",
                severity="medium",
                file=file,
                line=action.line,
                rule=RULE,
                fix_hint=FIX,
                category="code",
                why=WHY,
                details={"cwe": "CWE-352", "controller": action.controller, "action": action.method},
            )
        )
    return findings
