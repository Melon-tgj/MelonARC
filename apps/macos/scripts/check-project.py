#!/usr/bin/env python3
"""Structural checks for the Xcode project.

This machine has no Xcode, so the checks below are what can honestly be verified
before the file reaches a macOS runner:

  * the project file parses as an old-style property list;
  * every object identifier that is referenced is defined, and every defined
    object is reachable from the root;
  * every file reference points at a file that exists in the tree (the embedded
    core and the built products excepted — the first is a build input, the
    others do not exist until the build runs);
  * every Swift source in the app and test directories is compiled by exactly the
    target it belongs to, and nothing else is;
  * the shared scheme names targets that exist and products the project builds.

Exit status is 1 when a check fails, so CI can run it before xcodebuild and get a
sentence instead of a compiler error about a missing file.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "MelonARC.xcodeproj" / "project.pbxproj"
SCHEME = ROOT / "MelonARC.xcodeproj" / "xcshareddata" / "xcschemes" / "MelonARC.xcscheme"
APP_ICON = ROOT / "MelonARC" / "Resources" / "Assets.xcassets" / "AppIcon.appiconset"

IDENTIFIER = re.compile(r"^[0-9A-F]{24}$")
PRODUCTS = {"MelonARC.app", "MelonARCTests.xctest", "MelonARCUITests.xctest"}


class ParseError(Exception):
    pass


class Parser:
    """A parser for the NeXTSTEP-style plist Xcode writes."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.index = 0

    def parse(self):
        value = self.value()
        self.skip()
        if self.index != len(self.text):
            raise ParseError(f"trailing content at offset {self.index}")
        return value

    def skip(self) -> None:
        while self.index < len(self.text):
            char = self.text[self.index]
            if char in " \t\r\n":
                self.index += 1
            elif self.text.startswith("/*", self.index):
                end = self.text.find("*/", self.index + 2)
                if end < 0:
                    raise ParseError("unterminated block comment")
                self.index = end + 2
            elif self.text.startswith("//", self.index):
                end = self.text.find("\n", self.index)
                self.index = len(self.text) if end < 0 else end + 1
            else:
                return

    def value(self):
        self.skip()
        if self.index >= len(self.text):
            raise ParseError("unexpected end of file")
        char = self.text[self.index]
        if char == "{":
            return self.dictionary()
        if char == "(":
            return self.array()
        if char == '"':
            return self.quoted()
        return self.bare()

    def dictionary(self) -> dict:
        self.expect("{")
        result = {}
        while True:
            self.skip()
            if self.peek() == "}":
                self.index += 1
                return result
            key = self.value()
            self.expect("=")
            value = self.value()
            self.expect(";")
            if not isinstance(key, str):
                raise ParseError(f"a dictionary key is not a string: {key!r}")
            result[key] = value

    def array(self) -> list:
        self.expect("(")
        result = []
        while True:
            self.skip()
            if self.peek() == ")":
                self.index += 1
                return result
            result.append(self.value())
            self.skip()
            if self.peek() == ",":
                self.index += 1
            elif self.peek() != ")":
                raise ParseError(f"expected , or ) at offset {self.index}")

    def quoted(self) -> str:
        assert self.peek() == '"'
        self.index += 1
        out = []
        while self.index < len(self.text):
            char = self.text[self.index]
            if char == "\\":
                out.append(self.text[self.index : self.index + 2])
                self.index += 2
                continue
            if char == '"':
                self.index += 1
                return "".join(out)
            out.append(char)
            self.index += 1
        raise ParseError("unterminated string")

    def bare(self) -> str:
        start = self.index
        while self.index < len(self.text) and self.text[self.index] not in " \t\r\n{}()=;,\"":
            self.index += 1
        if start == self.index:
            raise ParseError(f"empty token at offset {self.index}")
        return self.text[start : self.index]

    def peek(self) -> str:
        self.skip()
        return self.text[self.index] if self.index < len(self.text) else ""

    def expect(self, char: str) -> None:
        self.skip()
        if self.peek() != char:
            raise ParseError(f"expected {char!r} at offset {self.index}")
        self.index += 1


def walk(node, visit):
    """Calls visit on every identifier-looking string in the tree."""
    if isinstance(node, str):
        if IDENTIFIER.match(node):
            visit(node)
    elif isinstance(node, dict):
        for value in node.values():
            walk(value, visit)
    elif isinstance(node, list):
        for value in node:
            walk(value, visit)


def main() -> int:
    failures: list[str] = []
    notes: list[str] = []

    text = PROJECT.read_text(encoding="utf-8")
    if not text.startswith("// !$*UTF8*$!"):
        failures.append("the project file does not start with the UTF-8 marker Xcode writes")

    try:
        root = Parser(text).parse()
    except ParseError as error:
        print(f"FAIL: the project file does not parse: {error}")
        return 1

    objects = root.get("objects")
    if not isinstance(objects, dict):
        print("FAIL: the project file has no objects dictionary")
        return 1
    root_object = root.get("rootObject")
    if root_object not in objects:
        failures.append(f"rootObject {root_object} is not defined")

    # 1. Every referenced identifier is defined, and the definitions are reachable.
    undefined: set[str] = set()

    def check(identifier: str) -> None:
        if identifier not in objects:
            undefined.add(identifier)

    walk(root, check)
    for identifier in sorted(undefined):
        failures.append(f"identifier {identifier} is referenced but not defined")

    if root_object in objects:
        seen: set[str] = set()
        pending = [root_object]
        while pending:
            current = pending.pop()
            if current in seen or current not in objects:
                continue
            seen.add(current)
            walk(objects[current], lambda value: pending.append(value))
        orphans = sorted(set(objects) - seen)
        for identifier in orphans:
            isas = objects[identifier].get("isa", "?") if isinstance(objects[identifier], dict) else "?"
            notes.append(f"object {identifier} ({isas}) is not reachable from the root")

    # 2. File references point at files that exist.
    for identifier, entry in objects.items():
        if not isinstance(entry, dict) or entry.get("isa") != "PBXFileReference":
            continue
        path = entry.get("path")
        tree = entry.get("sourceTree")
        if tree != "<group>" or not isinstance(path, str):
            continue
        resolved = resolve_path(objects, identifier)
        if resolved is None:
            failures.append(f"file reference {identifier} ({path}) has no parent group")
            continue
        if resolved.name in PRODUCTS or entry.get("lastKnownFileType") == "compiled.mach-o.executable":
            # Built products appear at build time; the core is a build input.
            continue
        if not resolved.exists():
            failures.append(f"file reference {path} points at {resolved}, which does not exist")

    # 3. The Swift sources are compiled by the targets they belong to.
    app_sources = source_files(objects, "1A0000000000000000000050")
    test_sources = source_files(objects, "1A0000000000000000000054")
    ui_test_sources = source_files(objects, "1A0000000000000000000057")
    expected_app = {
        path.name
        for directory in ("App", "Services", "UI")
        for path in (ROOT / "MelonARC" / directory).glob("*.swift")
    }
    expected_tests = {path.name for path in (ROOT / "MelonARCTests").glob("*.swift")}
    services = {path.name for path in (ROOT / "MelonARC" / "Services").glob("*.swift")}
    registry = {"PanelRegistry.swift"}

    missing_app = expected_app - app_sources
    for name in sorted(missing_app):
        failures.append(f"{name} is not compiled by the app target")
    unexpected_app = app_sources - expected_app
    for name in sorted(unexpected_app):
        failures.append(f"{name} is compiled by the app target but does not exist in App, Services or UI")

    missing_tests = expected_tests - test_sources
    for name in sorted(missing_tests):
        failures.append(f"{name} is not compiled by the test target")
    unexpected_tests = test_sources - expected_tests - services - registry
    for name in sorted(unexpected_tests):
        failures.append(f"{name} is compiled by the test target but is not a test or a shared service")
    for name in sorted(services | registry):
        if name not in test_sources:
            failures.append(f"{name} is a shared source but the test target does not compile it")

    expected_ui_tests = {path.name for path in (ROOT / "MelonARCUITests").glob("*.swift")}
    missing_ui_tests = expected_ui_tests - ui_test_sources
    for name in sorted(missing_ui_tests):
        failures.append(f"{name} is not compiled by the UI test target")
    unexpected_ui_tests = ui_test_sources - expected_ui_tests
    for name in sorted(unexpected_ui_tests):
        failures.append(f"{name} is compiled by the UI test target but is not a UI test")

    # 4. Resources and the embedded core are in the phases that need them.
    resources = phase_file_names(objects, "1A0000000000000000000052")
    for name in (
        "Assets.xcassets",
        "Localizable.xcstrings",
        "LICENSE",
        "THIRD-PARTY-NOTICES.md",
        "SECURITY.md",
        "README.md",
        "PRIVACY.md",
    ):
        if name not in resources:
            failures.append(f"{name} is not copied by the app's resources phase")
    copied = phase_file_names(objects, "1A0000000000000000000053")
    if "melonarc-core" not in copied:
        failures.append("melonarc-core is not copied into the bundle")

    # 5. The shared scheme names what the project builds.
    if not SCHEME.exists():
        failures.append("the shared scheme is missing")
    else:
        scheme = SCHEME.read_text(encoding="utf-8")
        for identifier in set(re.findall(r'BlueprintIdentifier = "([0-9A-F]{24})"', scheme)):
            if identifier not in objects:
                failures.append(f"the scheme names target {identifier}, which is not defined")
        for name in set(re.findall(r'BuildableName = "([^"]+)"', scheme)):
            if name not in PRODUCTS:
                failures.append(f"the scheme names product {name}, which this project does not build")
        if 'ReferencedContainer = "container:MelonARC.xcodeproj"' not in scheme:
            failures.append("the scheme does not reference the project container")
        if "TestableReference" not in scheme:
            failures.append("the scheme has no test action, so `xcodebuild test` would run nothing")

    # 6. The ten traditional macOS icon slots must each have a PNG of the
    #    declared pixel size. actool silently skips a 1024x1024 / 1x image.
    catalog = APP_ICON / "Contents.json"
    if not catalog.exists():
        failures.append("the app icon catalog is missing")
    else:
        try:
            images = json.loads(catalog.read_text(encoding="utf-8"))["images"]
        except (OSError, ValueError, KeyError) as error:
            failures.append(f"the app icon catalog does not parse: {error}")
            images = []
        slots = [(image.get("idiom"), image.get("size"), image.get("scale")) for image in images]
        sizes = ("16x16", "32x32", "128x128", "256x256", "512x512")
        expected_slots = {("mac", size, scale) for size in sizes for scale in ("1x", "2x")}
        if len(images) != 10:
            failures.append(f"the app icon catalog has {len(images)} images, expected 10")
        for slot in sorted(set(slots)):
            if slots.count(slot) != 1:
                failures.append(f"the app icon slot {slot} is declared more than once")
        if set(slots) != expected_slots:
            failures.append("the app icon must declare the ten mac 1x/2x slots, each once")
        for image in images:
            filename = image.get("filename")
            size, scale = image.get("size"), image.get("scale")
            if not isinstance(filename, str):
                failures.append("an app icon slot has no filename")
                continue
            path = APP_ICON / filename
            if not path.exists():
                failures.append(f"the app icon file {filename} does not exist")
                continue
            if size not in sizes or scale not in ("1x", "2x"):
                continue
            pixels = int(size.split("x", 1)[0]) * (2 if scale == "2x" else 1)
            try:
                width, height = png_size(path)
            except (OSError, ValueError) as error:
                failures.append(f"{filename} is not a readable PNG: {error}")
                continue
            if (width, height) != (pixels, pixels):
                failures.append(f"{filename} is {width}x{height}, expected {pixels}x{pixels}")

    for note in notes:
        print(f"note: {note}")
    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        return 1
    print(
        f"ok: project has {len(objects)} objects, {len(app_sources)} app sources, "
        f"{len(test_sources)} test sources, {len(ui_test_sources)} UI test sources"
    )
    return 0


def png_size(path: Path) -> tuple[int, int]:
    """Reads the IHDR dimensions without an image library."""
    data = path.read_bytes()[:24]
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError("not a PNG with an IHDR chunk")
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def resolve_path(objects: dict, identifier: str) -> Path | None:
    """Resolves a file reference through its parent groups."""
    parents = {}
    for parent_id, entry in objects.items():
        if isinstance(entry, dict) and entry.get("isa") == "PBXGroup":
            for child in entry.get("children", []):
                parents[child] = parent_id

    parts: list[str] = []
    current = identifier
    while True:
        entry = objects.get(current)
        if not isinstance(entry, dict):
            return None
        if entry.get("isa") == "PBXFileReference" and isinstance(entry.get("path"), str):
            parts.append(entry["path"])
        elif entry.get("isa") == "PBXGroup":
            if isinstance(entry.get("path"), str):
                parts.append(entry["path"])
            elif entry.get("name") == "Products":
                return None
        parent = parents.get(current)
        if parent is None:
            break
        current = parent
    return ROOT.joinpath(*reversed(parts))


def phase_file_names(objects: dict, phase_id: str) -> set[str]:
    phase = objects.get(phase_id)
    if not isinstance(phase, dict):
        return set()
    names = set()
    for build_file in phase.get("files", []):
        entry = objects.get(build_file)
        if not isinstance(entry, dict):
            continue
        reference = objects.get(entry.get("fileRef"))
        if isinstance(reference, dict) and isinstance(reference.get("path"), str):
            names.add(Path(reference["path"]).name)
    return names


def source_files(objects: dict, phase_id: str) -> set[str]:
    return phase_file_names(objects, phase_id)


if __name__ == "__main__":
    sys.exit(main())
