#!/usr/bin/env python3
"""Checks the string catalog and its use from the sources.

Three things can go wrong with a hand-written catalog and none of them is caught
by the compiler:

  * a key used in the sources is missing, so the interface shows the key itself;
  * a translation is missing, so a Chinese window shows English;
  * the two languages disagree about the number or kind of placeholders, which
    turns `String(format:)` into garbage or a crash.

The keys built at runtime (`core.state.…`, `core.failure.reason.…`, `error.…`)
cannot be found by scanning literals, so the families are listed here and checked
for completeness. Keep the lists in step with the enums in
`Services/CoreSupervisor.swift` and `Services/APIClient.swift`.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "MelonARC" / "Resources" / "Localizable.xcstrings"
SOURCES = [ROOT / "MelonARC", ROOT / "MelonARCTests"]

LANGUAGES = ("en", "zh-Hans")
PLACEHOLDER = re.compile(r"%(?:@|d|ld|s|f|\.\d+f|%)")
LITERAL_KEY = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")

# The call forms that take a localization key. Anything else that looks like a
# dotted lower-case word (a file name, an SF Symbol, a notification name) is not a
# key and must not be reported as a missing one.
CALL_PATTERNS = [
    re.compile(r'Text\(\s*"([^"\\\n]+)"'),
    re.compile(r'Button\(\s*"([^"\\\n]+)"'),
    re.compile(r'Window\(\s*"([^"\\\n]+)"'),
    re.compile(r'titleKey:\s*"([^"\\\n]+)"'),
    re.compile(r'Localization\.text\(\s*"([^"\\\n]+)"'),
    re.compile(r'Localization\.format\(\s*"([^"\\\n]+)"'),
    re.compile(r'String\(localized:\s*"([^"\\\n]+)"'),
    re.compile(r'NSLocalizedString\(\s*"([^"\\\n]+)"'),
]

RUNTIME_FAMILIES = [
    "core.state.starting",
    "core.state.running",
    "core.state.stopped",
    "core.state.crashed",
    "core.failure.reason.core_missing",
    "core.failure.reason.configuration_missing",
    "core.failure.reason.port_in_use",
    "core.failure.reason.exited",
    "core.failure.reason.signalled",
    "core.failure.reason.startup_budget",
    "core.failure.reason.launch_failed",
    "error.token_missing",
    "error.unauthorized",
    "error.unreachable",
    "error.http_status",
    "error.decoding",
    "error.unknown_subscription",
    "error.not_found",
    "error.method_not_allowed",
    "error.bad_request",
    "error.conflict",
    "error.unprocessable_entity",
    "error.internal_error",
    "error.reload_unavailable",
    "error.config_not_written",
    "error.config_not_file_backed",
    "error.explain_failed",
    "error.no_configuration_directory",
    "error.invalid_address",
    "error.unusable_data_directory",
    "error.data_directory_changed",
    "system_proxy.state.off",
    "system_proxy.state.configured",
    "system_proxy.state.pending_restart",
    "system_proxy.state.applied",
    "system_proxy.state.recovery_failed",
    "system_proxy.state.unknown",
]


def main() -> int:
    failures: list[str] = []

    try:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        print(f"FAIL: the catalog is not valid JSON: {error}")
        return 1

    if catalog.get("version") != "1.0":
        failures.append(f"unexpected catalog version {catalog.get('version')!r}")
    if catalog.get("sourceLanguage") != "en":
        failures.append(f"unexpected source language {catalog.get('sourceLanguage')!r}")

    strings = catalog.get("strings")
    if not isinstance(strings, dict) or not strings:
        print("FAIL: the catalog has no strings")
        return 1

    for key, entry in strings.items():
        localizations = entry.get("localizations", {})
        values = {}
        for language in LANGUAGES:
            unit = localizations.get(language, {}).get("stringUnit", {})
            value = unit.get("value")
            state = unit.get("state")
            if not isinstance(value, str) or not value:
                failures.append(f"{key}: no {language} value")
                continue
            if state != "translated":
                failures.append(f"{key}: {language} is {state!r}, not translated")
            values[language] = value
        if len(values) == len(LANGUAGES):
            shapes = {language: sorted(PLACEHOLDER.findall(text)) for language, text in values.items()}
            if shapes["en"] != shapes["zh-Hans"]:
                failures.append(
                    f"{key}: placeholders differ between languages "
                    f"(en {shapes['en']}, zh-Hans {shapes['zh-Hans']})"
                )

    for key in RUNTIME_FAMILIES:
        if key not in strings:
            failures.append(f"{key}: built at runtime but missing from the catalog")

    literals: set[str] = set()
    for directory in SOURCES:
        for path in directory.rglob("*.swift"):
            text = path.read_text(encoding="utf-8")
            for pattern in CALL_PATTERNS:
                for candidate in pattern.findall(text):
                    if LITERAL_KEY.match(candidate):
                        literals.add(candidate)

    for key in sorted(literals - set(strings)):
        failures.append(f"{key}: used in the sources but missing from the catalog")

    for key in sorted(set(strings) - literals - set(RUNTIME_FAMILIES)):
        print(f"note: {key} is not referenced by a literal; it is built at runtime or unused")

    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        return 1
    print(f"ok: {len(strings)} keys, {len(literals)} literal references, {len(LANGUAGES)} languages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
