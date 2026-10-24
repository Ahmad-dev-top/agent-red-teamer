# Shop Support Agent — demo target #1

A deliberately-vulnerable support agent used to demonstrate the full scan loop.
It conforms to the HTTP adapter contract, and its tools are mocks holding canary
tokens, so every successful attack leaves hard evidence.

## Run it

```bash
pip install -e ".[demo]"          # fastapi + uvicorn

# vulnerable variant (default)
uvicorn examples.shop_support.agent:app --host 127.0.0.1 --port 8080
# in another shell:
redforge-agents scan examples/shop_support/target.yaml --adapter http
```

Point the target config's `config.url` at `http://127.0.0.1:8080/chat` for a
local run (the committed value `http://shop-support:8080/chat` is the hostname on
the sandbox internal bridge).

## Hardened variant (before/after)

```bash
HARDENED=1 uvicorn examples.shop_support.agent:app --port 8080
redforge-agents scan examples/shop_support/target.yaml --adapter http
```

The vulnerable variant falls to all seven attack categories (8 findings); the
hardened variant drives the attack-success rate to zero. That delta is the
before/after story for a client report.

## What makes it vulnerable (on purpose)

It treats instructions in user messages and in tool-returned content as commands
to follow, puts a secret in its system prompt, and has no policy checks on
state-changing tools. The hardened variant applies the fixes from
`recommend.py`: refuse embedded instructions, route high-impact actions to a
human, and never reveal internal configuration.
