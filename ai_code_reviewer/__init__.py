"""ai-code-reviewer: rule-based security review of source code.

No LLM, no paid AI, no network calls. A deterministic, rule-based engine
that scans source files (or a unified git diff) for common security
anti-patterns and reports each finding with severity, location,
explanation, and a suggested fix.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
