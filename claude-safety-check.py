#!/usr/bin/env python3
"""
claude-safety-check.py — Multi-Agent Prompt Injection & Supply Chain Scanner
Detects malicious instructions embedded in repos/skill packs targeting any AI agent.
"""

import os
import re
import sys
import json
import base64
import argparse
import unicodedata
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ─── Agent-specific files to always inspect ───────────────────────────────────

AGENT_FILES = {
    "Claude Code":      [
        "CLAUDE.md", ".claude/settings.json", ".claude/settings.local.json",
        ".claude/CLAUDE.md",
    ],
    "Claude Code (commands/agents)": [],   # discovered dynamically
    "Cursor":           [".cursorrules", ".cursor/rules"],
    "GitHub Copilot":   [".github/copilot-instructions.md"],
    "Windsurf":         [".windsurfrules", ".windsurf/rules"],
    "Aider":            [".aider.conf.yml", "aider.md", "CONVENTIONS.md"],
    "Continue":         [".continue/config.json", ".continue/config.yaml"],
    "Cline / Roo":      [".clinerules", ".roo/rules", ".roomodes"],
    "Devin":            [".devin/instructions.md"],
    "OpenHands":        [".openhands/microagents"],
    "OpenAI Codex":     ["AGENTS.md"],
    "Mentat":           [".mentat_config.yaml"],
    "Copilot (VSCode)": [".vscode/settings.json"],
    "Generic":          ["SYSTEM_PROMPT.md", "system_prompt.md", "PROMPT.md",
                         ".prompt", "prompt.txt", "instructions.md",
                         "INSTRUCTIONS.md"],
}

# Extensions to scan for content
TEXT_EXTENSIONS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg",
    ".ini", ".sh", ".bash", ".zsh", ".py", ".js", ".ts",
    ".mdc", ".mdx", ".rst", ".xml", ".env",
}

# ─── Detection rules ──────────────────────────────────────────────────────────

# Rules tagged with skip_code=True are not applied to source code files
CODE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rb", ".java", ".c", ".cpp", ".cs", ".rs"}


@dataclass
class Rule:
    id: str
    severity: str          # LOW / MEDIUM / HIGH / CRITICAL
    description: str
    pattern: re.Pattern
    context_lines: int = 2
    skip_code: bool = False  # skip applying to source code files


RULES: list[Rule] = [

    # ── Prompt injection — override / ignore ──────────────────────────────────
    Rule("INJ-001", "CRITICAL",
         "Override / ignore previous instructions",
         re.compile(
             r"(?<!\w)(ignore|disregard|forget|bypass|supersede)\s.{0,40}"
             r"(previous|prior|above|all\s+(?:the\s+)?(?:previous\s+)?(?:system\s+)?)"
             r"(instructions|rules|constraints|prompts?)",
             re.I), skip_code=True),

    Rule("INJ-002", "CRITICAL",
         "Unrestricted / unconstrained persona injection",
         re.compile(
             # Only flag role hijacks that explicitly remove safety/restrictions
             # "act as a pentester" is fine; "act as an AI with no restrictions" is not
             r"(act as|you are now|pretend (you are|to be)|from now on you).{0,60}"
             r"(no (restrictions|limits|guardrails|filters|censorship|safety)"
             r"|without (restrictions|limits|constraints|ethics|morals)"
             r"|uncensored|unrestricted|unfiltered|jailbroken"
             r"|ignore (your |all )?(ethics|guidelines|safety|policies|rules)"
             r"|no (ethical|moral|safety) (rules|guidelines|constraints))",
             re.I), skip_code=True),

    Rule("INJ-003", "HIGH",
         "New task / new instruction injection",
         re.compile(
             r"(new task:|new instruction:|system override:|STOP[.!]?\s+New|"
             r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|\[INST\])",
             re.I), skip_code=True),

    Rule("INJ-004", "HIGH",
         "DAN / jailbreak pattern",
         re.compile(
             r"(DAN mode|jailbreak|do anything now|developer mode enabled"
             r"|safety (off|disabled|bypassed)|no (restrictions|limits|guardrails))",
             re.I), skip_code=True),

    Rule("INJ-005", "MEDIUM",
         "Confidentiality suppression (hide output from user)",
         re.compile(
             r"(do not (tell|inform|show|reveal|mention) the user"
             r"|keep (this|it|that) (secret|hidden|confidential)"
             r"|never (mention|disclose|reveal) (this|that|these))",
             re.I)),

    # ── Exfiltration ──────────────────────────────────────────────────────────
    Rule("EXF-001", "CRITICAL",
         "Credential / secret file access",
         re.compile(
             r"(~/\.ssh|~/\.aws|~/\.gnupg|~\/\.config|/etc/passwd|/etc/shadow"
             r"|(?<![.\w])\.env(?!\w)|id_rsa|id_ed25519|credentials\.json|\.netrc"
             r"|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET)",
             re.I)),

    Rule("EXF-002", "CRITICAL",
         "curl/wget to external URL (possible exfiltration)",
         re.compile(
             r"(curl|wget|fetch|http\.get)\s.{0,80}(https?://)"
             r"(?!localhost|127\.|0\.0\.0\.0|internal|local)",
             re.I)),

    Rule("EXF-003", "HIGH",
         "Data piped to external endpoint",
         re.compile(
             r"\|\s*(curl|wget|nc|netcat|ncat|socat|python|bash)\s.{0,60}https?://",
             re.I)),

    Rule("EXF-004", "HIGH",
         "DNS exfiltration pattern",
         re.compile(
             r"(nslookup|dig|host)\s+\$|ping\s+-c\s+1\s+\$|"
             r"\$\(.+\)\.(burp|interact\.sh|oastify|canarytokens|ngrok)",
             re.I)),

    Rule("EXF-005", "MEDIUM",
         "subprocess / os.system with variable expansion",
         re.compile(
             r"(os\.system|subprocess\.(run|Popen|call)|eval|exec)\s*\(",
             re.I)),

    # ── Claude Code hook injection ─────────────────────────────────────────────
    Rule("HOOK-001", "CRITICAL",
         "settings.json hook with shell command",
         re.compile(
             r'"hooks"\s*:\s*\{.*?"command"\s*:\s*"[^"]*(curl|wget|bash|sh|python|nc)',
             re.I | re.S)),

    Rule("HOOK-002", "HIGH",
         "settings.json hook referencing external URL",
         re.compile(
             r'"command"\s*:\s*"[^"]*https?://',
             re.I)),

    # ── Cursor / Windsurf / Copilot rule injection ─────────────────────────────
    Rule("RULE-001", "HIGH",
         "Cursor/Windsurf rule with system override",
         re.compile(
             r"(alwaysApply|globs).*?(ignore|override|bypass|disregard)",
             re.I | re.S)),

    # ── Hidden unicode / steganography ────────────────────────────────────────
    Rule("UNI-001", "HIGH",
         "Zero-width / invisible unicode characters (excluding emoji ZWJ)",
         re.compile(
             # Excludes U+200D (ZWJ) which is used legitimately in emoji sequences
             r"[\u200b\u200c\u2060\u2061\u2062\u2063\u2064"
             r"\ufeff\xad\u180e\u202a-\u202e\u2066-\u206f]")),

    Rule("UNI-002", "MEDIUM",
         "Unicode RTL override (text direction spoofing)",
         re.compile(r"[\u202E\u202D\u200F؜]")),

    Rule("UNI-003", "LOW",
         "Unusual unicode lookalike (homoglyph potential)",
         re.compile(
             r"[аеорсхі"   # Cyrillic lookalikes
             r"αεορυν]")),       # Greek lookalikes

    # ── Steganography in content ───────────────────────────────────────────────
    Rule("STEG-001", "HIGH",
         "Base64 blob embedded in markdown (>=60 chars)",
         re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/])")),

    Rule("STEG-002", "MEDIUM",
         "HTML comment hiding content in markdown",
         re.compile(r"<!--[\s\S]{20,}?-->")),

    Rule("STEG-003", "MEDIUM",
         "Invisible markdown link (empty text with URL)",
         re.compile(r"\[\s*\]\s*\(https?://[^)]+\)")),

    # ── Shell script risk ─────────────────────────────────────────────────────
    Rule("SH-001", "CRITICAL",
         "curl|bash / wget|sh install pattern",
         re.compile(r"(curl|wget).{0,80}\|\s*(ba)?sh", re.I)),

    Rule("SH-002", "HIGH",
         "Reverse shell pattern",
         re.compile(
             r"(bash -i|/dev/tcp/|nc -e|ncat -e|mkfifo.{0,30}nc"
             r"|python.*socket.*connect|socat.*EXEC)", re.I)),

    Rule("SH-003", "MEDIUM",
         "chmod +x on downloaded file",
         re.compile(r"chmod\s+\+x\s+/tmp/", re.I)),

    # ── Credential sent via URL parameter (ToxicSkills pattern) ──────────────
    Rule("EXF-006", "CRITICAL",
         "Credential / secret sent as URL parameter (ToxicSkills exfiltration)",
         re.compile(
             r"https?://[^\s\"']{4,}\?"
             r"[^\s\"']{0,60}(pw|pass|password|token|secret|key|cred|auth)=[^\s\"']{0,80}",
             re.I)),

    # ── MCP / tool server injection ───────────────────────────────────────────
    Rule("MCP-001", "HIGH",
         "MCP server pointing to non-localhost URL",
         re.compile(
             r'"(url|endpoint|host)"\s*:\s*"https?://'
             r'(?!localhost|127\.|0\.0\.0\.0)',
             re.I)),

    Rule("MCP-002", "MEDIUM",
         "MCP tool description with injection phrase",
         re.compile(
             r'"description"\s*:\s*"[^"]{0,200}'
             r'(ignore|override|new task|system prompt|forget)',
             re.I)),

    # ── Suspicious YAML frontmatter ───────────────────────────────────────────
    Rule("FM-001", "MEDIUM",
         "Frontmatter with unexpected system/role key",
         re.compile(
             r"^(system|role|persona|identity)\s*:\s*.+",
             re.I | re.M)),

    # ── Sensitive env vars ────────────────────────────────────────────────────
    Rule("ENV-001", "HIGH",
         "Hardcoded API key / token pattern",
         re.compile(
             r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|"
             r"AKIA[0-9A-Z]{16}|xoxb-[0-9]+-[a-zA-Z0-9]+"
             r"|anthropic[_-]api[_-]key\s*=\s*['\"][a-z0-9-]+)",
             re.I)),

    Rule("ENV-002", "MEDIUM",
         "Generic secret assignment in config",
         re.compile(
             r"(password|passwd|secret|token|api_key|private_key)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
             re.I)),

    # ── Destructive / data-manipulation actions ───────────────────────────────
    Rule("DATA-001", "CRITICAL",
         "Destructive file delete instruction",
         re.compile(
             r"(rm\s+-[rRf]{1,3}\s+[/~]"                        # rm -rf /path
             r"|shred\s+(-[a-z]+\s+)*[/~]"                       # shred file
             # Require a path or possessive ("all your files") to avoid doc FPs
             r"|(?:delete|remove|wipe|erase|destroy)\s+(?:all\s+)?(?:your\s+|the\s+|my\s+)?"
             r"(?:files?|data|records?|logs?|backups?|database)\s+(?:in|at|from|under)\s+[/~])",
             re.I), skip_code=True),

    Rule("DATA-002", "CRITICAL",
         "Remote data transfer to external host (rsync/scp/sftp)",
         re.compile(
             r"(rsync|scp|sftp)\s.{0,80}"
             r"(?!localhost|127\.|0\.0\.0\.0|internal)"
             r"[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:",
             re.I)),

    Rule("DATA-003", "CRITICAL",
         "Destructive database operation (DROP/TRUNCATE/DELETE)",
         re.compile(
             r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE"
             r"|DELETE\s+FROM\s+\w+\s*(?:WHERE\s+1\s*=\s*1|;|$))",
             re.I), skip_code=True),

    Rule("DATA-004", "HIGH",
         "Overwrite or modify sensitive system file",
         re.compile(
             r"(>\s*|tee\s+|write.{0,20})"
             r"(/etc/(passwd|shadow|sudoers|hosts|crontab|ssh)"
             r"|~/.ssh/(authorized_keys|known_hosts|config)"
             r"|~/(\.bashrc|\.zshrc|\.profile|\.bash_profile))",
             re.I)),

    Rule("DATA-005", "HIGH",
         "git push / transfer to non-local remote",
         re.compile(
             r"git\s+(push|remote\s+add).{0,80}"
             r"https?://(?!localhost|127\.|0\.0\.0\.0)"
             r"|git\s+push.{0,40}origin",
             re.I), skip_code=True),

    Rule("DATA-006", "HIGH",
         "Instruction to send / upload / transmit collected data",
         re.compile(
             r"(send|upload|transmit|forward|post|submit|exfiltrate)"
             r"\s.{0,60}"
             r"(to\s+(?:the\s+)?(server|endpoint|url|attacker|remote|external)"
             r"|https?://(?!localhost|127\.))",
             re.I), skip_code=True),

    # ── Supply chain — package manager hooks ──────────────────────────────────
    Rule("SC-001", "CRITICAL",
         "npm lifecycle hook with shell command (preinstall/postinstall)",
         re.compile(
             r'"(preinstall|postinstall|prepare|prepack|prepublish)"\s*:\s*"[^"]*'
             r'(curl|wget|bash|sh|python|node|exec|eval|nc\s)',
             re.I)),

    Rule("SC-002", "CRITICAL",
         "setup.py / pyproject install hook with shell command",
         re.compile(
             r"(cmdclass|build_ext|install_requires).{0,200}"
             r"(os\.system|subprocess|eval|exec|__import__)\s*\(",
             re.I | re.S)),

    Rule("SC-003", "HIGH",
         "GitHub Actions expression injection (untrusted input in run step)",
         re.compile(
             r"run\s*:\s*[|>]?\s*[^\n]*"
             r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review)"
             r"|github\.head_ref|github\.ref_name)",
             re.I)),

    Rule("SC-004", "HIGH",
         "GitHub Actions secrets or tokens exposed in log/echo",
         re.compile(
             r"(echo|run|::set-output).{0,40}"
             r"\$\{\{\s*secrets\.[A-Z_]+\s*\}\}",
             re.I)),

    # ── SSRF / cloud metadata access ──────────────────────────────────────────
    Rule("SSRF-001", "CRITICAL",
         "Cloud metadata endpoint access (SSRF / credential theft)",
         re.compile(
             r"(curl|wget|fetch|requests?\.get|http\.get).{0,60}"
             r"(169\.254\.169\.254"          # AWS/GCP/Azure IMDS
             r"|100\.100\.100\.200"          # Alibaba Cloud metadata
             r"|fd00:ec2::254"               # AWS IPv6 metadata
             r"|metadata\.google\.internal"
             r"|169\.254\.170\.2)",          # ECS task metadata
             re.I)),

    Rule("SSRF-002", "HIGH",
         "Instruction to fetch internal / non-routable URL",
         re.compile(
             r"(fetch|curl|wget|visit|open|access|load).{0,60}"
             r"(https?://(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.))",
             re.I), skip_code=True),

    # ── Persistence mechanisms ─────────────────────────────────────────────────
    Rule("PERSIST-001", "CRITICAL",
         "Crontab / scheduled task modification",
         re.compile(
             r"(crontab\s+-[el]|echo.{0,60}cron"
             r"|/etc/cron\.(d|daily|hourly|weekly|monthly)/"
             r"|at\s+now|schtasks\s+/create)",
             re.I)),

    Rule("PERSIST-002", "CRITICAL",
         "Systemd / launchd service installation",
         re.compile(
             r"(systemctl\s+(enable|start|daemon-reload)"
             r"|/etc/systemd/system/[^/]+\.service"
             r"|launchctl\s+(load|bootstrap)"
             r"|~/Library/LaunchAgents/)",
             re.I)),

    Rule("PERSIST-003", "HIGH",
         "SSH authorized_keys backdoor",
         re.compile(
             r"(>>?\s*~?/?(home/\w+/)?\.ssh/authorized_keys"
             r"|echo.{0,80}authorized_keys"
             r"|ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{40,})",
             re.I)),

    Rule("PERSIST-004", "HIGH",
         "Self-modifying agent instructions (writing to CLAUDE.md / agent config)",
         re.compile(
             r"(write|append|echo|cat|tee).{0,60}"
             r"(CLAUDE\.md|\.cursorrules|\.windsurfrules|\.clinerules"
             r"|\.claude/(settings|CLAUDE)|AGENTS\.md)",
             re.I)),

    # ── Privilege escalation ───────────────────────────────────────────────────
    Rule("PRIV-001", "CRITICAL",
         "sudo without password / sudoers modification",
         re.compile(
             r"(NOPASSWD\s*:\s*ALL"
             r"|sudo\s+-S\s+echo"               # echo password to sudo -S
             r"|echo.{0,40}\|\s*sudo\s+tee.{0,40}sudoers"
             r"|visudo)",
             re.I)),

    Rule("PRIV-002", "HIGH",
         "Setuid / setgid bit on executable",
         re.compile(
             r"chmod\s+(u\+s|g\+s|[0-9]{4})\s+",
             re.I)),

    Rule("PRIV-003", "HIGH",
         "Environment variable hijack (PATH / LD_PRELOAD poisoning)",
         re.compile(
             r"(export\s+)?(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PATH)\s*="
             r"['\"]?(/tmp/|/dev/shm/|\$HOME/\.[a-z])",
             re.I)),

    # ── Obfuscation / evasion ─────────────────────────────────────────────────
    Rule("OBF-001", "HIGH",
         "Shell hex/octal encoding of dangerous commands",
         re.compile(
             r"(\\x[0-9a-f]{2}){4,}"           # \x69\x67\x6e\x6f\x72\x65
             r"|(\\[0-7]{3}){4,}"               # octal encoding
             r"|\$'\\.+'"                       # $'\x...' ANSI-C quoting
             , re.I)),

    Rule("OBF-002", "HIGH",
         "String concatenation to bypass keyword detection",
         re.compile(
             r"('ign'\s*\+\s*'ore'|'dis'\s*\+\s*'regard'"
             r"|\"ign\"\s*\+\s*\"ore\"|chr\(\d+\)\s*\+\s*chr\(\d+\))",
             re.I)),

    Rule("OBF-003", "MEDIUM",
         "eval / exec of encoded or dynamic string",
         re.compile(
             r"(eval|exec)\s*\(\s*"
             r"(base64|decode|decompress|zlib|rot13|bytes\.fromhex)",
             re.I)),

    Rule("OBF-004", "MEDIUM",
         "Markdown CSS/style trick to hide text from user",
         re.compile(
             r"<(span|div|p|font)[^>]*"
             r"(color\s*:\s*(white|#fff|#ffffff|transparent)"
             r"|font-size\s*:\s*[01](px|pt)?"
             r"|display\s*:\s*none"
             r"|visibility\s*:\s*hidden)",
             re.I)),

    # ── Template / code injection ─────────────────────────────────────────────
    Rule("TMPL-001", "HIGH",
         "Server-side template injection pattern",
         re.compile(
             r"(\{\{[^}]{0,80}(config|request|__class__|__mro__|popen|system)"
             r"|\$\{[^}]{0,80}(Runtime|exec|system|process)"
             r"|#\{[^}]{0,80}(system|exec|`)})",
             re.I)),

    Rule("TMPL-002", "MEDIUM",
         "Shell variable / command substitution in instruction text",
         re.compile(
             r"(\$\([^)]{5,}\)|\`[^`]{5,}\`)"    # $(cmd) or `cmd`
             r"(?!.*#)",                            # not in a comment
             re.I)),
]

# ─── Risk scoring ─────────────────────────────────────────────────────────────

SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 20}
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def aggregate_severity(scores: list[str]) -> str:
    if not scores:
        return "CLEAN"
    idx = max(SEVERITY_ORDER.index(s) for s in scores)
    return SEVERITY_ORDER[idx]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def is_likely_base64_payload(match: str) -> bool:
    """Filter out false positives: try decode and check for printable content."""
    try:
        decoded = base64.b64decode(match + "==").decode("utf-8", errors="replace")
        printable = sum(1 for c in decoded if c.isprintable())
        return printable / max(len(decoded), 1) > 0.7
    except Exception:
        return False


def read_text(path: Path) -> Optional[str]:
    for enc in ("utf-8", "latin-1"):
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    return None


def get_lines(text: str, match_start: int, context: int = 2) -> tuple[int, list[str]]:
    lines = text.splitlines()
    pos = 0
    lineno = 1
    for i, line in enumerate(lines):
        if pos + len(line) >= match_start:
            lineno = i + 1
            break
        pos += len(line) + 1
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno + context)
    return lineno, lines[start:end]

# ─── Scan engine ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: str
    description: str
    file: str
    lineno: int
    snippet: list[str]
    match: str


@dataclass
class FileResult:
    path: str
    agent_tag: Optional[str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return aggregate_severity([f.severity for f in self.findings])

    @property
    def score(self) -> int:
        return sum(SEVERITY_SCORE[f.severity] for f in self.findings)


def strip_code_fences(text: str) -> str:
    """Remove content inside ``` fences so injection rules don't fire on code examples."""
    return re.sub(r"```[\s\S]*?```", lambda m: "\n" * m.group(0).count("\n"), text)


def scan_file(path: Path, agent_tag: Optional[str] = None) -> FileResult:
    result = FileResult(path=str(path), agent_tag=agent_tag)
    text = read_text(path)
    if text is None:
        return result

    is_code = path.suffix.lower() in CODE_EXTENSIONS
    # For markdown files, use a fence-stripped version for injection rules
    is_markdown = path.suffix.lower() in {".md", ".mdx", ".mdc"}
    text_no_fences = strip_code_fences(text) if is_markdown else text

    for rule in RULES:
        if rule.skip_code and is_code:
            continue

        scan_text = text_no_fences if (rule.skip_code and is_markdown) else text

        for m in rule.pattern.finditer(scan_text):
            matched = m.group(0)

            # Filter base64 false positives
            if rule.id == "STEG-001" and not is_likely_base64_payload(matched):
                continue

            lineno, snippet = get_lines(text, m.start(), rule.context_lines)
            result.findings.append(Finding(
                rule_id=rule.id,
                severity=rule.severity,
                description=rule.description,
                file=str(path),
                lineno=lineno,
                snippet=snippet,
                match=matched[:120] + ("…" if len(matched) > 120 else ""),
            ))

    return result


def discover_files(root: Path) -> list[tuple[Path, Optional[str]]]:
    """Return (path, agent_tag) for all files to scan."""
    found: list[tuple[Path, Optional[str]]] = []
    seen: set[Path] = set()

    # 1. Walk known agent config files
    for agent, paths in AGENT_FILES.items():
        for rel in paths:
            p = root / rel
            if p.is_file() and p not in seen:
                found.append((p, agent))
                seen.add(p)
            elif p.is_dir():
                for child in p.rglob("*"):
                    if child.is_file() and child not in seen:
                        found.append((child, agent))
                        seen.add(child)

    # 2. Discover dynamic Claude Code agents/commands
    for pattern in [".claude/commands/**/*.md", ".claude/agents/**/*.md",
                    ".claude/skills/**/*.md"]:
        for p in root.glob(pattern):
            if p not in seen:
                found.append((p, "Claude Code (commands/agents)"))
                seen.add(p)

    # 3. Walk all text files in the repo
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p in seen:
            continue
        if p.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        # Skip binary-ish files >1MB
        if p.stat().st_size > 1_000_000:
            continue
        found.append((p, None))
        seen.add(p)

    return found

# ─── Report ───────────────────────────────────────────────────────────────────

COLORS = {
    "CRITICAL": "\033[1;31m",  # bold red
    "HIGH":     "\033[0;31m",  # red
    "MEDIUM":   "\033[0;33m",  # yellow
    "LOW":      "\033[0;36m",  # cyan
    "CLEAN":    "\033[0;32m",  # green
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}

def c(color: str, text: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return COLORS.get(color, "") + text + COLORS["RESET"]


def print_report(results: list[FileResult], root: Path,
                 no_color: bool = False, json_out: bool = False,
                 min_severity: str = "LOW") -> int:
    """Print report. Returns exit code (0=clean, 1=findings)."""

    threshold = SEVERITY_ORDER.index(min_severity)
    results = [r for r in results if r.findings]
    results = [r for r in results
               if SEVERITY_ORDER.index(r.severity) >= threshold]
    results.sort(key=lambda r: r.score, reverse=True)

    if json_out:
        out = []
        for r in results:
            out.append({
                "file": r.path,
                "agent": r.agent_tag,
                "severity": r.severity,
                "score": r.score,
                "findings": [
                    {"rule": f.rule_id, "severity": f.severity,
                     "description": f.description, "line": f.lineno,
                     "match": f.match}
                    for f in r.findings
                ],
            })
        print(json.dumps(out, indent=2))
        return 1 if results else 0

    print()
    print(c("BOLD", f"  Multi-Agent Safety Scanner", no_color))
    print(c("DIM",  f"  Root: {root}", no_color))
    print()

    if not results:
        print(c("CLEAN", "  ✓ No issues found above threshold.", no_color))
        print()
        return 0

    # Summary bar
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for f in r.findings:
            by_sev[f.severity] += 1

    parts = [c(s, f"{by_sev[s]} {s}", no_color)
             for s in reversed(SEVERITY_ORDER) if by_sev[s]]
    print("  " + "  ·  ".join(parts))
    print()

    for r in results:
        rel = Path(r.path).relative_to(root) if Path(r.path).is_relative_to(root) else Path(r.path)
        agent_label = f"  [{r.agent_tag}]" if r.agent_tag else ""
        print(c("BOLD", f"  {rel}{agent_label}", no_color),
              c(r.severity, f"  ▶ {r.severity}  (score: {r.score})", no_color))

        for f in r.findings:
            print(c(f.severity, f"    [{f.rule_id}] {f.description}", no_color))
            print(c("DIM", f"      line {f.lineno}: {f.match[:100]}", no_color))
            for line in f.snippet:
                print(c("DIM", f"        │ {line}", no_color))
        print()

    print(c("BOLD", f"  {len(results)} file(s) flagged.", no_color))
    print()
    return 1


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Multi-agent prompt injection & supply chain scanner")
    parser.add_argument("path", nargs="?", default=".",
                        help="Directory or file to scan (default: .)")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="LOW",
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON instead of human-readable report")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    parser.add_argument("--list-rules", action="store_true",
                        help="List all detection rules and exit")
    args = parser.parse_args()

    if args.list_rules:
        print(f"{'ID':<12} {'SEV':<10} {'DESCRIPTION'}")
        print("-" * 70)
        for rule in RULES:
            print(f"{rule.id:<12} {rule.severity:<10} {rule.description}")
        return 0

    root = Path(args.path).resolve()

    if root.is_file():
        files = [(root, None)]
    elif root.is_dir():
        files = discover_files(root)
    else:
        print(f"Error: {root} is not a file or directory", file=sys.stderr)
        return 2

    results = []
    for path, agent_tag in files:
        result = scan_file(path, agent_tag)
        results.append(result)

    return print_report(results, root,
                        no_color=args.no_color,
                        json_out=args.json,
                        min_severity=args.min_severity)


if __name__ == "__main__":
    sys.exit(main())
