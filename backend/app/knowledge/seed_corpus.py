"""
Seed knowledge corpus for the retrieval agent.

These entries are written from scratch for this project -- summarizing
well-known, public CWE/OWASP categories in original wording -- not scraped
or copy-pasted from cwe.mitre.org or owasp.org (which aren't reachable from
this environment's network allowlist anyway). This stands in for the "real"
corpus until the NVD/OSV/GHSA ingestion pipeline (app/knowledge/ghsa_ingest.py)
can run against live data with a GitHub token and outside this sandbox's
rate limits.
"""
SEED_DOCUMENTS: list[dict] = [
    {
        "source": "cwe", "external_id": "CWE-89",
        "title": "CWE-89: SQL Injection",
        "content": (
            "Occurs when untrusted input is concatenated directly into a SQL query "
            "string instead of being passed as a bound parameter. An attacker can "
            "supply input containing SQL syntax to alter the query's logic, read or "
            "modify data outside the intended scope, or in some database engines "
            "execute further commands. The standard fix is parameterized queries or "
            "an ORM's query builder, never string concatenation or f-strings for query text."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-78",
        "title": "CWE-78: OS Command Injection",
        "content": (
            "Arises when user-controlled data is passed into a shell command, "
            "typically via functions that invoke a shell (shell=True in Python's "
            "subprocess, os.system, backticks). Attackers can chain additional "
            "commands using shell metacharacters. Mitigation: avoid the shell "
            "entirely by passing an argument list to subprocess with shell=False, "
            "and validate/allowlist any input that must influence the command."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-79",
        "title": "CWE-79: Cross-Site Scripting (XSS)",
        "content": (
            "Happens when untrusted input is rendered into an HTML page without "
            "proper encoding, letting an attacker inject script that runs in "
            "another user's browser session. Reflected, stored, and DOM-based "
            "variants exist. Mitigation: contextual output encoding (auto-escaping "
            "template engines), a strict Content-Security-Policy, and avoiding "
            "direct innerHTML assignment of untrusted strings."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-95",
        "title": "CWE-95: Improper Neutralization of Directives (Eval Injection)",
        "content": (
            "Occurs when untrusted input reaches eval(), exec(), or similar "
            "dynamic-code-execution constructs, letting an attacker run arbitrary "
            "code in the host process. There is rarely a legitimate reason to eval "
            "untrusted input; use safe parsers (e.g. ast.literal_eval for literals, "
            "json.loads for structured data) instead."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-502",
        "title": "CWE-502: Deserialization of Untrusted Data",
        "content": (
            "Deserializers for formats like pickle (Python), Java serialization, or "
            "unsafe YAML loaders can be coerced into instantiating arbitrary "
            "objects or invoking arbitrary code as a side effect of deserializing "
            "attacker-controlled bytes. Prefer data-only formats (JSON) for "
            "untrusted input, and if pickle/YAML must be used, restrict to "
            "yaml.safe_load or a similarly sandboxed loader and never unpickle "
            "data from an untrusted source."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-798",
        "title": "CWE-798: Use of Hard-coded Credentials",
        "content": (
            "Embedding API keys, passwords, or tokens directly in source code means "
            "anyone with repository access (including through git history, forks, "
            "or leaked builds) has the credential, and rotation requires a code "
            "change and redeploy. Mitigation: load secrets from environment "
            "variables or a secrets manager, and add secret-scanning to CI to catch "
            "accidental commits."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-327",
        "title": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "content": (
            "Algorithms like MD5 and SHA-1 are broken for collision resistance and "
            "unsuitable for password hashing (they're fast, which helps "
            "brute-forcing) or integrity-critical uses. Use a dedicated password "
            "hashing function (bcrypt, scrypt, or Argon2) for credentials, and "
            "SHA-256/SHA-3 for general integrity checks where collision resistance "
            "matters."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-918",
        "title": "CWE-918: Server-Side Request Forgery (SSRF)",
        "content": (
            "Occurs when a server fetches a URL supplied (directly or indirectly) "
            "by an untrusted user without validating the destination, letting an "
            "attacker make the server issue requests to internal-only services, "
            "cloud metadata endpoints, or other unintended targets. Mitigation: "
            "allowlist permitted destination hosts/schemes, block requests to "
            "private/link-local IP ranges, and avoid following redirects blindly."
        ),
    },
    {
        "source": "cwe", "external_id": "CWE-22",
        "title": "CWE-22: Path Traversal",
        "content": (
            "Happens when user input is used to build a filesystem path without "
            "neutralizing sequences like '../', letting an attacker read or write "
            "files outside the intended directory. Mitigation: resolve the "
            "requested path and verify it is still within the intended base "
            "directory before use, rather than trying to blocklist traversal "
            "sequences."
        ),
    },
    {
        "source": "owasp", "external_id": "A01:2021",
        "title": "OWASP A01:2021 - Broken Access Control",
        "content": (
            "The most common OWASP Top 10 category: users acting outside their "
            "intended permissions, e.g. accessing another user's records by "
            "changing an ID in a URL (IDOR), or reaching admin functionality "
            "without an authorization check. Mitigation: deny by default, enforce "
            "authorization server-side on every request (never trust client-side "
            "checks alone), and centralize the access-control logic rather than "
            "duplicating checks per endpoint."
        ),
    },
    {
        "source": "owasp", "external_id": "A02:2021",
        "title": "OWASP A02:2021 - Cryptographic Failures",
        "content": (
            "Covers exposure of sensitive data due to missing or weak encryption "
            "in transit or at rest, weak key management, or use of deprecated "
            "algorithms. Mitigation: encrypt sensitive data at rest, enforce TLS "
            "everywhere, and use vetted cryptographic libraries rather than "
            "hand-rolled implementations."
        ),
    },
    {
        "source": "owasp", "external_id": "A03:2021",
        "title": "OWASP A03:2021 - Injection",
        "content": (
            "Covers SQL, OS command, LDAP, and similar injection classes where "
            "untrusted data is interpreted as code/commands by an interpreter. "
            "Mitigation: use parameterized interfaces (prepared statements, ORM "
            "query builders, subprocess argument lists) rather than string "
            "concatenation, and validate input against a strict allowlist where "
            "feasible."
        ),
    },
    {
        "source": "owasp", "external_id": "A08:2021",
        "title": "OWASP A08:2021 - Software and Data Integrity Failures",
        "content": (
            "Covers code and infrastructure that doesn't verify integrity, "
            "including insecure deserialization and unsigned/unverified CI/CD "
            "pipelines and auto-update mechanisms. Mitigation: verify digital "
            "signatures on dependencies and updates, and avoid deserializing data "
            "from untrusted sources without integrity checks."
        ),
    },
]
