# CURSOR.md — build & operations guide for RedForge Agents

You (Cursor) are the **implementation, testing, and iteration** engineer. The
architecture, the typed contracts, the judge principle, and the 6-week plan below
are fixed decisions — follow them. When something is ambiguous, prefer the option
that keeps the pipeline **typed, sandboxed, and proof-first**.

## 0. What we're building

An autonomous red-teamer for tool-using AI agents. Input: a `target.yaml`
describing an agent. Output: a report of proven vulnerabilities (each with hard
evidence + a reproduction transcript + a fix) and an attack-success-rate (ASR)
before/after hardening.

Pipeline: `target + seeds → adapter → (sandboxed) agent → deterministic judge →
findings → report`.

### Non-negotiable principles
1. **Proof-first judge.** Success is decided ONLY by `judge/deterministic.py`
   (a tool-call log entry or a leaked canary). The LLM judge is a second opinion
   recorded for an agreement metric and can NEVER flip a verdict. This is the
   whole product's credibility — never weaken it.
2. **Typed hand-offs.** Every boundary uses a Pydantic model from `schemas.py`.
   No free-form dicts across modules.
3. **Attacks are data.** The seed library is YAML in `seeds/`. Growing coverage
   means adding YAML, not code.
4. **Untrusted code stays sandboxed.** The target agent and its mock tools run in
   the Docker sandbox (no network, or an internal-only bridge to mocks). Host
   code orchestrates; it never runs target code directly.
5. **Every attack category has a vulnerable fixture and a safe fixture.** The
   judge must flag the first and pass the second. No exceptions.

## 1. Environment & gate

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # add RFA_ANTHROPIC_API_KEY for the attacker/judge LLM
docker build -t rfa-sandbox:latest -f docker/sandbox.Dockerfile .
```

Definition of done for any change: `ruff check src tests`, `mypy src`, and
`pytest -q` are all green, and new behaviour has a test. Keep every hand-off
typed, every untrusted run sandboxed, every finding backed by hard evidence.

## 2. Repository map (what exists now — Week 1 ✅)

| Path | Role |
|---|---|
| `schemas.py` | typed contracts: Target, Attack, Attempt, Finding, Report, Verdict |
| `judge/deterministic.py` | **the anti-cheat core** — proof checks per ProofType |
| `judge/judge.py` | deterministic-authoritative; LLM second opinion only |
| `adapters/` | TargetAdapter protocol + `http` and `stub` adapters |
| `seeds/loader.py` + `seeds/*.yaml` | the YAML attack library (all 7 categories) |
| `campaign.py` | the scan loop: adapter → judge → findings → report |
| `recommend.py` | per-category fix recommendations |
| `sandbox/runner.py` | hardened Docker runner (no-net / internal bridge) |
| `reporting.py` | terminal table + JSON report (HTML template is Week 4) |
| `cli.py` | `redforge-agents validate | seeds | scan` |
| `examples/shop_support/` | demo target config |

## 3. Coding conventions
- Python ≥3.11, full type hints, `from __future__ import annotations`.
- Pydantic v2; validate at boundaries. No `os.environ` outside `config.py`.
- No `print`; use `logging_conf.get_logger`.
- Adapters and the LLM are injected so the loop and judge test with stubs (no
  Docker, no API key). Keep it that way.

## 4. The 6-week plan

Each week ends with something that runs end to end.

### Week 1 — Harness ✅ (COMPLETE)
Done, including the live demo agent:
- `examples/shop_support/agent.py` — a deliberately-vulnerable FastAPI support
  agent conforming to the HTTP adapter contract, with mock tools holding the
  canaries. Runs deterministically (no API key). Vulnerable variant falls to all
  7 categories (8 findings); `HARDENED=1` drives ASR to zero.
- `tests/test_demo_agent.py` drives the real seed library against the live agent
  through the real judge, in-process (TestClient), and asserts findings vulnerable
  / none hardened.
- **AC met:** `pip install -e ".[demo]"`, run the agent with uvicorn, then
  `redforge-agents scan examples/shop_support/target.yaml --adapter http`
  produces evidence-backed findings.

Small optional polish for you: a docker-compose that runs the demo agent on the
sandbox internal bridge (so `--adapter http` hits it inside the sandbox network
rather than localhost). Not blocking — the agent already runs end to end.

### Week 2 — Single-turn attack library
- Grow `seeds/` to ~100 attacks across the 7 categories (reuse public payloads
  where licenses allow; keep each as YAML with a concrete `success` proof).
- Persist runs/attempts/findings to SQLite (`storage.py`).
- **AC:** a scan runs the full library and saves results; ASR table per category.

### Week 3 — Attacker agent (multi-turn)
- `attacker.py`: an LLM attacker (strong model) that, on a failed seed, mutates
  and chains follow-up turns up to `max_turns`, feeding the agent's replies back.
  Plugs into `campaign.py` by producing the turns the adapter sends.
- Indirect injection through poisoned emails/pages/docs; the **inbox assistant**
  as demo #2.
- **AC:** multi-turn attacks confirm breaks single-turn seeds miss; agreement
  metric (deterministic vs LLM judge) reported on a hand-labelled sample.

### Week 4 — MCP + reporting
- MCP adapter + MCP tool-poisoning attacks; the **MCP dev agent** as demo #3.
- HTML report (Jinja2 → `reporting/html.py`): severity, OWASP mapping, full
  transcripts, the fix per finding. Export to PDF.
- **AC:** a shareable HTML report for a full scan.

### Week 5 — Harden & re-test
- Apply the recommended fixes to the demo agents; re-scan; compute **ASR before
  vs after** per category. GitHub Action to re-scan on agent change.
- **AC:** a before/after ASR table showing the fixes work.

### Week 6 — Launch
- Benchmark results table across the 3 demos, README "where it failed and how it
  recovered" section, 3-minute Loom, offer page.

## 5. The proof contract (read before touching the judge)
`judge/deterministic.py` is the heart. A finding exists only when the harness
observes one of: a forbidden tool call, a tripwire fired with out-of-policy args,
a canary value in an output/outbound sink, the agent obeying injected content
(marker), or a blown budget. Each returns the exact evidence string. Never route
this decision through the LLM, and never emit a Finding without a populated
`evidence`.

## 6. Safety & legal (keep intact)
- Sandbox: `--network none` by default; mock services reachable only on an
  internal bridge, never the public internet. Don't relax the run-time flags.
- Only scan agents owned or authorized in writing; staging/sandbox only, never
  production data. Ship the scope-agreement template with the offer.

## 7. First tasks, in order (Week 1 is done — start at Week 2)
1. Add `storage.py` (SQLite): persist runs, attempts, findings, transcripts.
2. Grow `seeds/` toward ~100 attacks across the 7 categories (YAML only).
3. (Optional) docker-compose to run the demo agent on the sandbox bridge.
4. Then Week 3: the multi-turn attacker agent (`attacker.py`) + the inbox demo.
Run `ruff` / `mypy` / `pytest` after each. Keep the judge deterministic-first.
