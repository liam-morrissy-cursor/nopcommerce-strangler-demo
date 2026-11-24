"""Dependency check built on `dotnet list package --vulnerable --include-transitive`."""
from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .advisories import AdvisoryResolver, advisory_id_from_url
from .model import SEVERITY_ORDER, Finding, finding_id, normalize_severity, severity_rank
from .projects import introduced_by, load_project, lowest_projects

WHY = "{package} {version} has a published advisory; anything using this code path inherits the vulnerability."
WHY_WITH_SUMMARY = "{summary} ({advisory}) in {package} {version}, shipped by {projects} project(s)."


@dataclass
class VulnerableHit:
    project: str
    package: str
    resolved_version: str
    requested_version: str | None
    severity: str
    advisory_url: str
    transitive: bool
    frameworks: list[str] = field(default_factory=list)


def parse_vulnerable_report(report: dict) -> list[VulnerableHit]:
    """Flatten `dotnet list package --vulnerable --format json` output into one hit per
    (project, package, version, advisory), merging target frameworks."""
    hits: dict[tuple, VulnerableHit] = {}
    for project in report.get("projects") or []:
        project_path = project.get("path", "")
        for framework in project.get("frameworks") or []:
            tfm = framework.get("framework", "")
            for key, transitive in (("topLevelPackages", False), ("transitivePackages", True)):
                for package in framework.get(key) or []:
                    for vuln in package.get("vulnerabilities") or []:
                        resolved = package.get("resolvedVersion") or package.get("requestedVersion") or ""
                        ident = (project_path, package["id"].lower(), resolved, vuln.get("advisoryurl", ""))
                        hit = hits.get(ident)
                        if hit is None:
                            hit = hits[ident] = VulnerableHit(
                                project=project_path,
                                package=package["id"],
                                resolved_version=resolved,
                                requested_version=package.get("requestedVersion"),
                                severity=normalize_severity(vuln.get("severity")),
                                advisory_url=vuln.get("advisoryurl", ""),
                                transitive=transitive,
                            )
                        if tfm and tfm not in hit.frameworks:
                            hit.frameworks.append(tfm)
    return list(hits.values())


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _max_version(versions: list[str]) -> str | None:
    from .advisories import _version_key

    return max(versions, key=_version_key) if versions else None


def hits_to_findings(
    hits: list[VulnerableHit], repo_root: Path, resolver: AdvisoryResolver | None = None
) -> list[Finding]:
    """One finding per vulnerable package version, listing every advisory and affected project.
    The location is where the fix belongs: the direct reference, or for transitive packages the
    lowest project in the reference graph that pulls the package in."""
    groups: dict[tuple[str, str], list[VulnerableHit]] = {}
    for hit in hits:
        groups.setdefault((hit.package.lower(), hit.resolved_version), []).append(hit)

    findings = []
    for (_, version), group in sorted(groups.items()):
        package = group[0].package
        direct_projects = sorted({Path(h.project) for h in group if not h.transitive})
        transitive_projects = sorted({Path(h.project) for h in group if h.transitive} - set(direct_projects))
        all_projects = direct_projects + transitive_projects

        advisories: dict[str, dict] = {}
        for hit in group:
            advisory = advisory_id_from_url(hit.advisory_url)
            if advisory not in advisories:
                info = resolver.resolve(advisory, package, version) if resolver else {}
                advisories[advisory] = {
                    "id": advisory,
                    "severity": hit.severity,
                    "url": hit.advisory_url,
                    "cve_id": info.get("cve_id"),
                    "summary": info.get("summary"),
                    "fixed_version": info.get("fixed_version"),
                }
        ordered = sorted(advisories.values(), key=lambda a: (-severity_rank(a["severity"]), a["id"]))
        severity = ordered[0]["severity"]
        fixed_versions = [a["fixed_version"] for a in ordered if a["fixed_version"]]
        fixed = _max_version(fixed_versions)
        unknown_fix = len(fixed_versions) < len(ordered)
        target_version = fixed or "<patched version>"
        if unknown_fix and fixed:
            target_version += " (check advisories without a listed patch)"

        file, line, via = all_projects[0], 1, []
        if direct_projects:
            anchor = lowest_projects(direct_projects)[0]
            ref = load_project(anchor, repo_root).locate(package)
            if ref:
                file, line = ref.file, ref.line
            fix = f"Bump {package} from {version} to {target_version} in {anchor.name}."
        else:
            anchor = lowest_projects(transitive_projects)[0]
            file = anchor
            via = introduced_by(anchor, package)
            project = load_project(anchor, repo_root)
            for name in via:
                ref = project.packages.get(name.lower())
                if ref:
                    file, line = ref.file, ref.line
                    break
            pulled = f" (pulled in by {', '.join(via)})" if via else ""
            fix = (
                f"Transitive dependency{pulled}. Pin <PackageReference Include=\"{package}\" Version=\"{target_version}\" /> "
                f"in {anchor.name}, or upgrade the parent package to a release that depends on a patched version."
            )

        if len(ordered) == 1:
            title = f"{package} {version} is affected by {ordered[0]['id']}"
            if ordered[0]["summary"]:
                title += f" ({ordered[0]['summary']})"
        else:
            counts = Counter(a["severity"] for a in ordered)
            breakdown = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts.get(s))
            title = f"{package} {version} is affected by {len(ordered)} advisories ({breakdown})"
        if len(all_projects) > 1:
            fix += f" Affects {len(all_projects)} projects."

        findings.append(
            Finding(
                id=finding_id("dependency", package.lower(), version),
                title=title,
                severity=severity,
                file=_rel(file, repo_root),
                line=line,
                rule="dependency/vulnerable-package",
                fix_hint=fix,
                category="dependency",
                why=(
                    WHY_WITH_SUMMARY.format(
                        summary=ordered[0]["summary"].rstrip("."), advisory=ordered[0]["id"],
                        package=package, version=version, projects=len(all_projects),
                    )
                    if ordered[0]["summary"]
                    else WHY.format(package=package, version=version)
                ),
                details={
                    "package": package,
                    "installed_version": version,
                    "fixed_version": fixed,
                    "transitive": not direct_projects,
                    "introduced_by": via,
                    "advisories": ordered,
                    "affected_projects": [_rel(p, repo_root) for p in all_projects],
                },
            )
        )
    return findings


def _dotnet(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"}
    return subprocess.run(["dotnet", *args], cwd=cwd, env=env, capture_output=True, text=True)


def run_dependency_check(
    targets: list[Path], repo_root: Path, resolver: AdvisoryResolver, restore: bool = True
) -> tuple[list[Finding], list[str]]:
    """Returns findings plus human-readable errors for targets that could not be checked."""
    hits: list[VulnerableHit] = []
    errors: list[str] = []
    for target in targets:
        rel = _rel(target, repo_root)
        if restore:
            result = _dotnet(["restore", str(target)], repo_root)
            if result.returncode != 0:
                errors.append(f"dotnet restore failed for {rel}: {result.stdout[-2000:]}{result.stderr[-2000:]}")
                continue
        result = _dotnet(
            ["list", str(target), "package", "--vulnerable", "--include-transitive", "--format", "json"],
            repo_root,
        )
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            errors.append(f"dotnet list package failed for {rel}: {result.stdout[-2000:]}{result.stderr[-2000:]}")
            continue
        for problem in report.get("problems") or []:
            errors.append(f"{rel}: {problem.get('text') or problem}")
        hits.extend(parse_vulnerable_report(report))
    return hits_to_findings(hits, repo_root, resolver), errors
