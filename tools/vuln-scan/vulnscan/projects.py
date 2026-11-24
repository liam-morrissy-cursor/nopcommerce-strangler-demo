"""Parse .csproj, Directory.Packages.props and .sln files to locate package declarations."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = {"bin", "obj", "node_modules", ".git", ".vs"}
_SLN_PROJECT = re.compile(r'^Project\("\{[^}]+\}"\)\s*=\s*"[^"]*",\s*"([^"]+\.csproj)"', re.M)


@dataclass
class PackageRef:
    name: str
    version: str | None
    file: Path
    line: int


@dataclass
class ProjectFile:
    path: Path
    packages: dict[str, PackageRef] = field(default_factory=dict)
    central_versions: dict[str, PackageRef] = field(default_factory=dict)

    def locate(self, package: str) -> PackageRef | None:
        """Where the version of `package` is declared for this project, if anywhere."""
        key = package.lower()
        ref = self.packages.get(key)
        central = self.central_versions.get(key)
        if ref and ref.version:
            return ref
        return central or ref


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _line_of(text_lines: list[str], element: str, name: str) -> int:
    pattern = re.compile(
        rf'<{element}\b[^>]*\b(Include|Update)\s*=\s*"{re.escape(name)}"', re.IGNORECASE
    )
    for number, line in enumerate(text_lines, start=1):
        if pattern.search(line):
            return number
    return 1


def parse_package_file(path: Path, element: str = "PackageReference") -> dict[str, PackageRef]:
    """Return package declarations (`PackageReference` or `PackageVersion`) keyed by lower-case id."""
    text = path.read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    root = ET.fromstring(text)
    result: dict[str, PackageRef] = {}
    for node in root.iter():
        if _strip_ns(node.tag) != element:
            continue
        name = node.get("Include") or node.get("Update")
        if not name:
            continue
        version = node.get("Version") or node.get("VersionOverride")
        if version is None:
            for child in node:
                if _strip_ns(child.tag) in ("Version", "VersionOverride") and child.text:
                    version = child.text.strip()
        result.setdefault(name.lower(), PackageRef(name, version, path, _line_of(lines, element, name)))
    return result


def find_central_props(project: Path, stop_at: Path) -> Path | None:
    """Closest Directory.Packages.props at or above the project directory, as MSBuild resolves it."""
    stop_at = stop_at.resolve()
    current = project.resolve().parent
    while True:
        candidate = current / "Directory.Packages.props"
        if candidate.is_file():
            return candidate
        if current == stop_at or current.parent == current:
            return None
        current = current.parent


def load_project(path: Path, repo_root: Path) -> ProjectFile:
    project = ProjectFile(path=path, packages=parse_package_file(path))
    props = find_central_props(path, repo_root)
    if props:
        project.central_versions = parse_package_file(props, "PackageVersion")
    return project


def project_references(path: Path) -> list[Path]:
    root = ET.fromstring(path.read_text(encoding="utf-8-sig"))
    refs = []
    for node in root.iter():
        if _strip_ns(node.tag) == "ProjectReference" and node.get("Include"):
            refs.append((path.parent / node.get("Include").replace("\\", "/")).resolve())
    return refs


def lowest_projects(projects: list[Path]) -> list[Path]:
    """Projects in the set that do not (transitively) reference another project in the set:
    the layer where a shared transitive dependency should be pinned."""
    members = {p.resolve() for p in projects}
    graph: dict[Path, list[Path]] = {}

    def refs(p: Path) -> list[Path]:
        if p not in graph:
            try:
                graph[p] = project_references(p)
            except (OSError, ET.ParseError):
                graph[p] = []
        return graph[p]

    def reaches_member(start: Path) -> bool:
        stack, seen = list(refs(start)), set()
        while stack:
            node = stack.pop()
            if node in members:
                return True
            if node not in seen:
                seen.add(node)
                stack.extend(refs(node))
        return False

    return sorted(p for p in members if not reaches_member(p))


def introduced_by(project: Path, package: str) -> list[str]:
    """Direct dependencies (packages or project references) of `project` whose closure pulls in
    `package`, read from obj/project.assets.json. Empty if the project is not restored."""
    import json

    assets_path = project.parent / "obj" / "project.assets.json"
    try:
        assets = json.loads(assets_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    target = package.lower()
    result: set[str] = set()
    for tfm, libraries in (assets.get("targets") or {}).items():
        deps = {key.split("/", 1)[0].lower(): {d.lower() for d in (lib.get("dependencies") or {})} for key, lib in libraries.items()}
        names = {key.split("/", 1)[0].lower(): key.split("/", 1)[0] for key in libraries}
        spec = assets.get("project") or {}
        direct = set()
        for fw in (spec.get("frameworks") or {}).values():
            direct.update(d.lower() for d in (fw.get("dependencies") or {}))
        for fw in ((spec.get("restore") or {}).get("frameworks") or {}).values():
            direct.update(Path(ref).stem.lower() for ref in (fw.get("projectReferences") or {}))
        for start in direct:
            if start == target:
                continue
            stack, seen = [start], set()
            while stack:
                node = stack.pop()
                if node == target:
                    result.add(names.get(start, start))
                    break
                if node not in seen:
                    seen.add(node)
                    stack.extend(deps.get(node, ()))
    return sorted(result)


def solution_projects(sln: Path) -> list[Path]:
    text = sln.read_text(encoding="utf-8-sig")
    return [(sln.parent / rel.replace("\\", "/")).resolve() for rel in _SLN_PROJECT.findall(text)]


def discover_projects(repo_root: Path, exclude: list[str] | None = None) -> list[Path]:
    exclude = [e.strip("/") for e in (exclude or [])]
    found = []
    for path in sorted(repo_root.rglob("*.csproj")):
        rel = path.relative_to(repo_root).as_posix()
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if any(rel == e or rel.startswith(e + "/") for e in exclude):
            continue
        found.append(path.resolve())
    return found


def scan_targets(repo_root: Path, solutions: list[Path], exclude: list[str] | None = None) -> list[Path]:
    """Solutions plus every project that none of them include, so nothing is silently skipped."""
    covered: set[Path] = set()
    for sln in solutions:
        covered.update(solution_projects(sln))
    stray = [p for p in discover_projects(repo_root, exclude) if p not in covered]
    return [s.resolve() for s in solutions] + stray
