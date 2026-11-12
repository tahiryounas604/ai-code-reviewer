"""Diff parsing and diff-only scanning tests."""

from ai_code_reviewer.diffscan import parse_diff, scan_diff

SAMPLE_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,5 @@
 import os
+api_key = "sk-live-9f8e7d6c5b4a39281706"
 
 def main():
-    api_key = "sk-live-9f8e7d6c5b4a39281706"
+    return None
diff --git a/util.py b/util.py
index 3333333..4444444 100644
--- a/util.py
+++ b/util.py
@@ -10,3 +10,4 @@
 def helper():
     return 1
+    x = eval(user_input)
"""


def test_parse_diff_returns_only_added_lines():
    parsed = parse_diff(SAMPLE_DIFF)
    assert set(parsed) == {"app.py", "util.py"}
    # added secret is line 2 of the new app.py; the added `return None` is line 5
    assert parsed["app.py"] == [
        (2, 'api_key = "sk-live-9f8e7d6c5b4a39281706"'),
        (5, "    return None"),
    ]
    # added eval is line 12 of the new util.py (hunk starts at 10, two context lines)
    assert parsed["util.py"] == [(12, "    x = eval(user_input)")]


def test_scan_diff_flags_only_added_lines():
    findings = scan_diff(SAMPLE_DIFF)
    rule_ids = {(f.rule_id, f.file, f.line) for f in findings}
    assert ("SEC001", "app.py", 2) in rule_ids
    assert ("DES002", "util.py", 12) in rule_ids
    # the REMOVED secret line must not be reported
    assert not any(f.file == "app.py" and f.line != 2 for f in findings)
    assert len(findings) == 2


def test_scan_diff_empty_diff():
    assert parse_diff("") == {}
    assert scan_diff("") == []


def test_scan_diff_respects_min_severity():
    findings = scan_diff(SAMPLE_DIFF, min_severity="critical")
    assert {f.rule_id for f in findings} == {"DES002"}


def test_parse_diff_new_file():
    diff = (
        "diff --git a/new.py b/new.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+import hashlib\n"
        "+hashlib.md5(data)\n"
    )
    findings = scan_diff(diff)
    assert len(findings) == 1
    assert findings[0].rule_id == "CRY001"
    assert findings[0].file == "new.py"
    assert findings[0].line == 2
