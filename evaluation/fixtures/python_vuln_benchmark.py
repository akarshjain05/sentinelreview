"""
A small, hand-written, labeled benchmark of Python code snippets used to
measure real precision/recall for SentinelReview's static analysis stage.

This is NOT the OWASP Benchmark or Juliet Test Suite -- those are Java-first
(OWASP Benchmark) or C/C++/Java-first (Juliet) and multi-gigabyte, which
doesn't fit this project's current Python scope or this environment's
constraints. Pulling and adapting a Python-relevant slice of Juliet (its
Python port is much smaller) is listed as a real next step in the README.

Every snippet here is original, written specifically for this benchmark --
not copied from any external source -- to avoid both copyright concerns and
overfitting to patterns a tool's authors already know about.

Each fixture has:
  - id: unique identifier
  - code: the Python source to analyze
  - vulnerable: ground truth -- is there a real vulnerability here at all
  - expected_cwe: ground truth CWE if vulnerable, else None
  - category: human label for grouping in the report
"""
from dataclasses import dataclass


@dataclass
class BenchmarkCase:
    id: str
    code: str
    vulnerable: bool
    expected_cwe: str | None
    category: str


BENCHMARK_CASES: list[BenchmarkCase] = [
    # ---- True positives: real vulnerabilities ----
    BenchmarkCase(
        id="sqli-01",
        code=(
            "def get_user(conn, name):\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
            "    return cursor.fetchone()\n"
        ),
        vulnerable=True, expected_cwe="CWE-89", category="sql_injection",
    ),
    BenchmarkCase(
        id="sqli-02",
        code=(
            "def search(conn, term):\n"
            "    q = f\"SELECT * FROM items WHERE name LIKE '%{term}%'\"\n"
            "    return conn.execute(q).fetchall()\n"
        ),
        vulnerable=True, expected_cwe="CWE-89", category="sql_injection",
    ),
    BenchmarkCase(
        id="cmdi-01",
        code=(
            "import subprocess\n"
            "def run(user_input):\n"
            "    subprocess.call(user_input, shell=True)\n"
        ),
        vulnerable=True, expected_cwe="CWE-78", category="command_injection",
    ),
    BenchmarkCase(
        id="cmdi-02",
        code=(
            "import os\n"
            "def ping(host):\n"
            "    os.system('ping -c 1 ' + host)\n"
        ),
        vulnerable=True, expected_cwe="CWE-78", category="command_injection",
    ),
    BenchmarkCase(
        id="deser-01",
        code=(
            "import pickle\n"
            "def load(raw_bytes):\n"
            "    return pickle.loads(raw_bytes)\n"
        ),
        vulnerable=True, expected_cwe="CWE-502", category="unsafe_deserialization",
    ),
    BenchmarkCase(
        id="eval-01",
        code=(
            "def compute(expr):\n"
            "    return eval(expr)\n"
        ),
        vulnerable=True, expected_cwe="CWE-95", category="unsafe_eval",
    ),
    BenchmarkCase(
        id="secret-01",
        code=(
            "API_KEY = 'sk_live_51H8f9aZ2xJmklsdf902'\n"
            "def get_client():\n"
            "    return Client(api_key=API_KEY)\n"
        ),
        vulnerable=True, expected_cwe="CWE-798", category="hardcoded_secret",
    ),
    BenchmarkCase(
        id="crypto-01",
        code=(
            "import hashlib\n"
            "def hash_password(pw):\n"
            "    return hashlib.md5(pw.encode()).hexdigest()\n"
        ),
        vulnerable=True, expected_cwe="CWE-327", category="weak_cryptography",
    ),
    BenchmarkCase(
        id="ssrf-01",
        code=(
            "import urllib.request\n"
            "def fetch(url):\n"
            "    return urllib.request.urlopen(url).read()\n"
        ),
        vulnerable=True, expected_cwe="CWE-918", category="ssrf",
    ),
    BenchmarkCase(
        id="yaml-01",
        code=(
            "import yaml\n"
            "def parse_config(raw):\n"
            "    return yaml.load(raw)\n"
        ),
        vulnerable=True, expected_cwe="CWE-502", category="unsafe_deserialization",
    ),

    # ---- True negatives: safe code that superficially resembles a vuln pattern ----
    BenchmarkCase(
        id="safe-sqli-01",
        code=(
            "def get_user(conn, name):\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute('SELECT * FROM users WHERE name = %s', (name,))\n"
            "    return cursor.fetchone()\n"
        ),
        vulnerable=False, expected_cwe=None, category="sql_injection",
    ),
    BenchmarkCase(
        id="safe-cmdi-01",
        code=(
            "import subprocess\n"
            "def run(args: list[str]):\n"
            "    subprocess.run(args, shell=False, check=True)\n"
        ),
        vulnerable=False, expected_cwe=None, category="command_injection",
    ),
    BenchmarkCase(
        id="safe-crypto-01",
        code=(
            "import hashlib\n"
            "def checksum(data: bytes):\n"
            "    return hashlib.sha256(data).hexdigest()\n"
        ),
        vulnerable=False, expected_cwe=None, category="weak_cryptography",
    ),
    BenchmarkCase(
        id="safe-secret-01",
        code=(
            "import os\n"
            "def get_client():\n"
            "    return Client(api_key=os.environ['API_KEY'])\n"
        ),
        vulnerable=False, expected_cwe=None, category="hardcoded_secret",
    ),
    BenchmarkCase(
        id="safe-generic-01",
        code=(
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
        ),
        vulnerable=False, expected_cwe=None, category="none",
    ),
    BenchmarkCase(
        id="safe-generic-02",
        code=(
            "class Cache:\n"
            "    def __init__(self):\n"
            "        self._data = {}\n"
            "    def get(self, key, default=None):\n"
            "        return self._data.get(key, default)\n"
        ),
        vulnerable=False, expected_cwe=None, category="none",
    ),
    BenchmarkCase(
        id="safe-yaml-01",
        code=(
            "import yaml\n"
            "def parse_config(raw):\n"
            "    return yaml.safe_load(raw)\n"
        ),
        vulnerable=False, expected_cwe=None, category="unsafe_deserialization",
    ),
]
