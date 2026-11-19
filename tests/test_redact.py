"""Secret redaction tests."""

from __future__ import annotations

import unittest

from shellsage.redact import PLACEHOLDER, Redactor, redact

# Fake credentials in realistic shapes. None of these are real.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
JWT = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dozjgNryP4J3jVmNHl0w5N"

LEAKS = [
    # (history line, secret that must disappear)
    (f"aws configure set aws_access_key_id {AWS_KEY}", AWS_KEY),
    ("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
    ("export DB_PASSWORD=hunter2", "hunter2"),
    ("export API_KEY='abc 123'", "abc 123"),
    ('TOKEN="s3cr3t value" ./deploy.sh', "s3cr3t value"),
    ("PGPASSWORD=topsecret psql -h db -U app", "topsecret"),
    ("mysql -u root -pSuperSecret1 mydb", "SuperSecret1"),
    ("sshpass -p 'my pass' ssh user@host", "my pass"),
    ("curl -u admin:letmein https://example.com/api", "letmein"),
    ("curl --user admin:letmein https://example.com/api", "letmein"),
    ("curl -H 'Authorization: Bearer abcdef123456.token' https://example.com", "abcdef123456"),
    ("curl -H 'Authorization: Basic dXNlcjpwYXNz' https://example.com", "dXNlcjpwYXNz"),
    ("git clone https://kavin:ghs3cr3t@github.com/x/y.git", "ghs3cr3t"),
    ("psql postgres://app:p4ssw0rd@db.internal:5432/prod", "p4ssw0rd"),
    ("redis-cli -u redis://default:r3dispass@cache:6379", "r3dispass"),
    (f"git remote set-url origin https://{GH_TOKEN}@github.com/x/y.git", GH_TOKEN),
    (f"echo {GH_TOKEN} | gh auth login --with-token", GH_TOKEN),
    ("export OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345", "abcdefghijklmnop"),
    ("echo sk-abcdefghijklmnopqrstuvwxyz012345", "abcdefghijklmnop"),
    ("SLACK=" + "xox" + "b-123456789012-abcdefghijklmnop ./notify", "123456789012"),
    (f"curl -H 'X-Auth: {JWT}' https://example.com", "dozjgNryP4J3jVmNHl0w5N"),
    ("docker login --password hunter2 -u kavin", "hunter2"),
    ("docker login --password=hunter2 -u kavin", "hunter2"),
    ("vault login --token s.abcdefgh12345678", "s.abcdefgh12345678"),
    ("tool --api-key ZXCVBNM12345", "ZXCVBNM12345"),
    ("echo 'password: correct horse'", "correct"),
    ('echo \'{"client_secret": "abc123def"}\' > cfg.json', "abc123def"),
    ("openssl enc -k 0123456789abcdef0123456789abcdef -in a", "0123456789abcdef0123456789abcdef"),
    (
        "echo -----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXk-----END OPENSSH PRIVATE KEY-----",
        "b3BlbnNzaC1rZXk",
    ),
]

HARMLESS = [
    "ls -la /var/log",
    "git commit -m 'fix token parser tests'",
    "cd ~/projects/shell-sage",
    "curl https://example.com/index.html",
    "ssh kavin@server.example.com",
    "grep -rn password_field src/",
    "python3 -m unittest discover -s tests",
    "scp report.pdf kavin@host:/tmp/",
    "git clone https://github.com/Kavin-Re/shell-sage.git",
]


class RedactionTests(unittest.TestCase):
    def test_secrets_are_removed(self) -> None:
        for line, secret in LEAKS:
            with self.subTest(line=line):
                cleaned = redact(line)
                self.assertNotIn(secret, cleaned)
                self.assertIn(PLACEHOLDER, cleaned)

    def test_harmless_lines_are_untouched(self) -> None:
        for line in HARMLESS:
            with self.subTest(line=line):
                self.assertEqual(redact(line), line)

    def test_context_around_secret_is_kept(self) -> None:
        self.assertEqual(
            redact("psql postgres://app:p4ss@db.internal:5432/prod"),
            f"psql postgres://{PLACEHOLDER}@db.internal:5432/prod",
        )
        self.assertEqual(redact("export DB_PASSWORD=hunter2"), f"export DB_PASSWORD={PLACEHOLDER}")
        self.assertEqual(
            redact("mysql -u root -pSuperSecret1 mydb"), f"mysql -u root -p{PLACEHOLDER} mydb"
        )

    def test_custom_patterns(self) -> None:
        redactor = Redactor([r"corp-[0-9]{6}", r"internal\.example\.org"])
        cleaned = redactor.redact("ssh deploy@internal.example.org --ticket corp-123456")
        self.assertNotIn("corp-123456", cleaned)
        self.assertNotIn("internal.example.org", cleaned)

    def test_redact_lines_keeps_order_and_length(self) -> None:
        lines = ["ls", "export TOKEN=abc", "pwd"]
        cleaned = Redactor().redact_lines(lines)
        self.assertEqual(len(cleaned), 3)
        self.assertEqual(cleaned[0], "ls")
        self.assertEqual(cleaned[2], "pwd")
        self.assertNotIn("abc", cleaned[1])

    def test_idempotent(self) -> None:
        for line, _secret in LEAKS:
            with self.subTest(line=line):
                once = redact(line)
                self.assertEqual(redact(once), once)


if __name__ == "__main__":
    unittest.main()
