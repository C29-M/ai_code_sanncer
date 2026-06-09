"""
Reference corpus of known-vulnerable code snippets for CodeBERT similarity scoring.

Each entry: {"vuln_type": str, "snippet": str, "label": "vulnerable" | "clean"}

The corpus has:
  - 2 vulnerable snippets per vuln_type (sqli, xss, rce, secrets, crypto) = 10 vulnerable
  - 6 clean snippets as negative examples
  - Total: 16 snippets

CodeBERT embeds each snippet on startup. At inference time we compute cosine
similarity between the query snippet's embedding and all corpus embeddings,
then return the max similarity against vulnerable entries (semantic_similarity).
"""

REFERENCE_CORPUS: list[dict] = [
    # --- SQL Injection ---
    {
        "vuln_type": "sqli",
        "label": "vulnerable",
        "snippet": "query = 'SELECT * FROM users WHERE name = ' + user_input\ncursor.execute(query)",
    },
    {
        "vuln_type": "sqli",
        "label": "vulnerable",
        "snippet": "db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`)",
    },

    # --- XSS ---
    {
        "vuln_type": "xss",
        "label": "vulnerable",
        "snippet": "document.getElementById('output').innerHTML = userInput;",
    },
    {
        "vuln_type": "xss",
        "label": "vulnerable",
        "snippet": "res.write('<div>' + req.query.name + '</div>');",
    },

    # --- RCE ---
    {
        "vuln_type": "rce",
        "label": "vulnerable",
        "snippet": "import os\nos.system('ls ' + user_input)",
    },
    {
        "vuln_type": "rce",
        "label": "vulnerable",
        "snippet": "eval(compile(user_code, '<string>', 'exec'))",
    },

    # --- Secrets ---
    {
        "vuln_type": "secrets",
        "label": "vulnerable",
        "snippet": "API_KEY = 'sk-prod-abc123xyz'\nrequests.get(url, headers={'Authorization': API_KEY})",
    },
    {
        "vuln_type": "secrets",
        "label": "vulnerable",
        "snippet": "password = 'P@ssw0rd123'\nconn = psycopg2.connect(password=password)",
    },

    # --- Weak crypto ---
    {
        "vuln_type": "crypto",
        "label": "vulnerable",
        "snippet": "import hashlib\nhash = hashlib.md5(password.encode()).hexdigest()",
    },
    {
        "vuln_type": "crypto",
        "label": "vulnerable",
        "snippet": "import random\ntoken = str(random.randint(0, 999999))",
    },

    # --- Clean snippets (negative examples) ---
    {
        "vuln_type": "none",
        "label": "clean",
        "snippet": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    },
    {
        "vuln_type": "none",
        "label": "clean",
        "snippet": "const output = document.createTextNode(userInput);\ndiv.appendChild(output);",
    },
    {
        "vuln_type": "none",
        "label": "clean",
        "snippet": "import subprocess\nresult = subprocess.run(['ls', '-la'], capture_output=True)",
    },
    {
        "vuln_type": "none",
        "label": "clean",
        "snippet": "import hashlib\nhash = hashlib.sha256(password.encode()).hexdigest()",
    },
    {
        "vuln_type": "none",
        "label": "clean",
        "snippet": "import secrets\ntoken = secrets.token_hex(32)",
    },
    {
        "vuln_type": "none",
        "label": "clean",
        "snippet": "API_KEY = os.environ.get('API_KEY')\nif not API_KEY:\n    raise ValueError('API_KEY not set')",
    },
]

# Pre-split for convenience
VULNERABLE_SNIPPETS = [e for e in REFERENCE_CORPUS if e["label"] == "vulnerable"]
CLEAN_SNIPPETS = [e for e in REFERENCE_CORPUS if e["label"] == "clean"]
