from __future__ import annotations

import json
import re

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class PackageJsonParser(DependencyParser):
    filenames = ["package.json"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps
        for section in ("dependencies", "devDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps


@register_parser
class PackageLockJsonParser(DependencyParser):
    filenames = ["package-lock.json"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps

        # v2/v3 format: "packages" field
        packages = data.get("packages", {})
        if packages:
            for path, info in packages.items():
                if not path:  # root package
                    continue
                name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
                version = info.get("version", "")
                if name and version:
                    deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
            return deps

        # v1 format: "dependencies" field
        self._parse_v1_deps(data.get("dependencies", {}), deps, filename)
        return deps

    def _parse_v1_deps(self, dependencies: dict, deps: list[Dependency], filename: str) -> None:
        for name, info in dependencies.items():
            version = info.get("version", "")
            if version:
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
            # Recurse into nested dependencies
            if "dependencies" in info:
                self._parse_v1_deps(info["dependencies"], deps, filename)


@register_parser
class YarnLockParser(DependencyParser):
    filenames = ["yarn.lock"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        seen = set()
        # Match patterns like: "package@^1.0.0": or package@^1.0.0:
        current_name = None
        for line in content.splitlines():
            # Header line: "name@version", "name@version":
            header = re.match(r'^"?(@?[^@\s"]+)@', line)
            if header:
                current_name = header.group(1)
                continue
            # Version line under a header
            if current_name:
                ver_match = re.match(r'^\s+version\s+"?([^"]+)"?', line)
                if ver_match:
                    version = ver_match.group(1)
                    if current_name not in seen:
                        seen.add(current_name)
                        deps.append(Dependency(name=current_name, version=version, ecosystem=self.ecosystem, source_file=filename))
                    current_name = None
        return deps


@register_parser
class PnpmLockParser(DependencyParser):
    filenames = ["pnpm-lock.yaml"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        seen = set()
        for line in content.splitlines():
            line = line.strip().strip("'\"")
            # Match pnpm package key patterns:
            # v6: /@scope/name@version or /name@version
            # v9: @scope/name@version or name@version (under packages:)
            m = re.match(
                r'^/?(@[^@/]+/[^@(]+|[^@/][^@(]*)@(\d+\.[^:()\s]+)',
                line,
            )
            if m:
                name = m.group(1).strip()
                version = m.group(2).strip().rstrip(":")
                if name and version and name not in seen:
                    seen.add(name)
                    deps.append(Dependency(
                        name=name, version=version,
                        ecosystem=self.ecosystem, source_file=filename,
                    ))
        return deps


@register_parser
class BunLockParser(DependencyParser):
    filenames = ["bun.lock", "bun.lockb"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        seen = set()

        # bun.lock (v1.2+) is JSON with "packages" as a flat object
        # where keys are package identifiers and values are arrays.
        # Format: {"packages": {"name": ["name@version", ...], ...}}
        # Also handles the text-based bun.lockb fallback via regex.
        try:
            data = json.loads(content)
            packages = data.get("packages", {})
            for key, val in packages.items():
                if not key or key == "":
                    continue
                # val is typically [resolution_string, ...] where
                # resolution_string is "name@version"
                if isinstance(val, list) and val:
                    resolution = val[0] if isinstance(val[0], str) else ""
                else:
                    resolution = ""

                # Extract name and version from resolution or key
                name, version = self._parse_bun_entry(key, resolution)
                if name and version and name not in seen:
                    seen.add(name)
                    deps.append(Dependency(
                        name=name, version=version,
                        ecosystem=self.ecosystem, source_file=filename,
                    ))
            return deps
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: regex for text-based format lines like "package@version"
        for line in content.splitlines():
            line = line.strip().strip('"')
            m = re.match(r'^(@?[^@\s]+)@(\d+\.\S+)', line)
            if m:
                name, version = m.group(1), m.group(2)
                if name not in seen:
                    seen.add(name)
                    deps.append(Dependency(
                        name=name, version=version,
                        ecosystem=self.ecosystem, source_file=filename,
                    ))
        return deps

    def _parse_bun_entry(self, key: str, resolution: str) -> tuple:
        """Extract name and version from a bun.lock entry."""
        # Try resolution string first: "express@4.18.2"
        if resolution:
            m = re.match(r'^(@?[^@]+)@(\d+\.\S+)', resolution)
            if m:
                return m.group(1), m.group(2)

        # Try key: might be "express" or "@scope/pkg"
        # Version might be in the resolution array
        # Key alone doesn't contain version, skip
        return None, None
