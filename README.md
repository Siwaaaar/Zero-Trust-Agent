# Zero-Trust-Agent

A zero-trust supply chain security auditor for AI agent ecosystems.  
**Scan before you install. Trust nothing by default.**

---

## What it does

Zero-Trust-Agent scans GitHub repos, local directories, skill packs, and MCP servers for malicious payloads before you install them into any AI agent environment.

It was built after real-world attacks were found in the wild, where credential exfiltration and Unicode steganography were hidden inside legitimate-looking skill files.

---

## What it detects

| Category | Rules | Examples |
|---|---|---|
| **Prompt injection** | INJ-001 → INJ-005 | `ignore previous instructions`, persona hijacks, DAN patterns |
| **Credential exfiltration** | EXF-001 → EXF-006 | `~/.ssh`, `curl \| bash`, `?pw=<secret>` URL params |
| **Claude Code hooks** | HOOK-001, HOOK-002 | `settings.json` hooks running shell commands |
| **Unicode steganography** | UNI-001 → UNI-003, STEG-001 → STEG-003 | Zero-width chars, TAG block (U+E0000), RTL overrides, base64 blobs |
| **Shell payloads** | SH-001 → SH-003 | `curl \| bash`, reverse shells, `/tmp` execution |
| **MCP server injection** | MCP-001, MCP-002 | External MCP endpoints, injected tool descriptions |
| **Supply chain hooks** | SC-001 → SC-004 | npm `postinstall`, `setup.py` exec, GitHub Actions injection |
| **Persistence** | PERSIST-001 → PERSIST-004 | Cron jobs, systemd services, SSH backdoors, self-modifying CLAUDE.md |
| **Privilege escalation** | PRIV-001 → PRIV-003 | `NOPASSWD`, setuid, PATH/LD_PRELOAD poisoning |
| **SSRF** | SSRF-001, SSRF-002 | Cloud metadata endpoints (169.254.169.254), internal URL access |
| **Obfuscation** | OBF-001 → OBF-004 | Hex/octal encoding, string splitting, CSS hidden text |
| **Secrets in config** | ENV-001, ENV-002 | Hardcoded API keys, tokens, passwords |

**50+ detection rules total.**

---

## Auto-trigger behavior

When installed as a Claude Code agent, Zero-Trust-Agent triggers automatically when:
- A GitHub URL is pasted alongside install intent
- A user asks to install a skill, MCP server, Cursor rule, or agent tool
- A suspicious `CLAUDE.md`, `.cursorrules`, or `AGENTS.md` is found
- A user asks "is this safe?"

---

## How to use

### As a Claude Code sub-agent

Install `0trust-agent.md` into your Claude Code agents directory:

```bash
cp 0trust-agent.md ~/.claude/agents/0trust-agent.md
```

Then in any Claude Code session, just paste a GitHub URL or path:

```
scan this before I install it: https://github.com/someone/some-skills
```

Claude will automatically clone the repo, run the scanner, deep-read all flagged files, filter false positives, and return a verdict.

### Scanner CLI (standalone)

The agent embeds the scanner and auto-writes it to `~/scripts/claude-safety-check.py` on first run. You can then use it directly:

```bash
# Scan a cloned repo
python3 ~/scripts/claude-safety-check.py /path/to/repo

# Scan a single file
python3 ~/scripts/claude-safety-check.py suspicious-skill.md

# Only show HIGH and above
python3 ~/scripts/claude-safety-check.py . --min-severity HIGH

# JSON output (for piping / CI)
python3 ~/scripts/claude-safety-check.py . --json

# List all detection rules
python3 ~/scripts/claude-safety-check.py --list-rules

# No ANSI colors (for logs)
python3 ~/scripts/claude-safety-check.py . --no-color
```

---

## Verdict system

| Verdict | Meaning |
|---|---|
| ✓ **SAFE** | No issues above LOW, or only benign LOWs. Safe to install. |
| ⚠ **REVIEW REQUIRED** | MEDIUM findings, or HIGH that may be false positives. Read before proceeding. |
| ✗ **DANGEROUS — DO NOT INSTALL** | Any confirmed CRITICAL. File, line, and payload documented. |

The agent distinguishes **true positives** from false positives:

| Likely false positive | Always real |
|---|---|
| `override` variable name in Python/JS | `curl … \| bash` anywhere |
| HTML comments inside code fences | `postinstall` hook running shell |
| ZWJ in emoji (`🧙‍♂️`) | URL with `?pw=` or `?token=` in skill |
| `process.env.TMPDIR` in JS | `NOPASSWD: ALL` in any file |
| XML comments in documentation | Instruction to write to `CLAUDE.md` |

---

## Real-world catches

| Finding | Technique |
|---|---|
| Password exfiltration via `?pw=<value>` URL parameter | Payload buried at line 408 of a 430-line skill file |
| Full file silently uploaded to attacker server | Mandatory backup step injected into normal workflow |
| RCE via `curl \| bash` to attacker-controlled IP | Base64-obfuscated inside skill prerequisites |
| System fingerprint exfiltration (`uname -a`) | Hidden inside a legitimate deployment "prerequisite" |
| Covert command execution (`open -a Calculator`) | Unicode TAG block U+E0000 — visually blank line in all editors |

---

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)
