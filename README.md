# red-team-api

**HTTP-API-first automated red-teaming for LLM-based agents.** Give it an AI agent's endpoint, get back a scored security report with auditable evidence.

## What it does

`red-team-api` runs adversarial scenarios against LLM-powered agents and returns findings with attacker prompts, target responses, and judge rationale — so you can decide if each finding is real, not take a black-box vendor's word for it.

**Differentiator:** API-first (not CLI-first), target-agnostic via adapters, LLM-as-judge with auditable evidence, single binary self-hostable.

## How it works

```
POST /v1/scans     →  enqueue a scan against a target
GET  /v1/scans/{id} →  poll progress + findings as they arrive
GET  /v1/scans/{id}/report →  markdown or JSON report
```

Each scan runs 5 attack categories in parallel:

| Category | What it tests |
|---|---|
| `direct_prompt_injection` | Can the agent be made to ignore its system prompt? |
| `system_prompt_extraction` | Can the system prompt be coaxed out verbatim? |
| `jailbreak_persona_switch` | Can safety alignment be bypassed via role-play/DAN/hypotheticals? |
| `indirect_prompt_injection` | Can instructions embedded in documents/content override behavior? |
| `output_handling_unsafe_content` | Does the agent emit raw HTML/JS/unsafe URLs in its output? |

Targets are accessed through swappable adapters (`openai_chat` for OpenAI-compatible endpoints, `generic_http` for anything with templated HTTP + JSONPath extraction).

The judge is Claude (via OpenRouter, OpenAI-compatible API) with Anthropic prompt caching enabled on the judge system prompt (~90% cache savings). Every finding includes the exact attack prompt, the target's full response, and the judge's reasoning.

## Quick start

```bash
git clone https://github.com/anomalyco/red-team-api.git
cd red-team-api
```

Create `.env` from the example and fill in your OpenRouter API key:

```bash
cp .env.example .env
# Edit .env: set OPENROUTER_API_KEY=sk-or-v1-...
```

Start the API and the bundled vulnerable stub target:

```bash
docker compose up -d
```

Verify both are running:

```bash
curl http://localhost:8000/health   # → {"status":"ok"}
curl http://localhost:8001/health   # → {"status":"ok","vulnerable":"True"}
```

Run a scan against the stub target:

```bash
curl -X POST http://localhost:8000/v1/scans \
  -H "Authorization: Bearer rtapi-dev-key-change-me" \
  -H "Content-Type: application/json" \
  -d @examples/stub-scan.json

# → {"scan_id":"scn_...","status":"queued"}
```

Poll for results:

```bash
curl http://localhost:8000/v1/scans/<scan_id> \
  -H "Authorization: Bearer rtapi-dev-key-change-me"
```

Get the report:

```bash
curl http://localhost:8000/v1/scans/<scan_id>/report \
  -H "Authorization: Bearer rtapi-dev-key-change-me" \
  -H "Accept: text/markdown"
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `OPENROUTER_API_KEY` | (required) | OpenRouter API key |
| `RTAPI_API_KEY` | `rtapi-dev-key-change-me` | API key protecting the red-team API itself |
| `RTAPI_JUDGE_MODEL` | `anthropic/claude-haiku-4-5` | Model used for judging attack success |
| `RTAPI_ATTACKER_MODEL` | `anthropic/claude-sonnet-4-6` | Model used for generating attack variants |
| `OPENROUTER_HTTP_REFERER` | (optional) | Sent as `HTTP-Referer` header to OpenRouter |
| `OPENROUTER_X_TITLE` | (optional) | Sent as `X-Title` header to OpenRouter |

Model IDs are validated against an allowlist: `^(anthropic|openai|google|meta-llama|mistralai)/.+$`

Per-scan model overrides are supported via the optional `models` field in the scan request body.

## API contract

### `POST /v1/scans`

```json
{
  "target": {
    "type": "openai_chat",
    "url": "https://target.example.com/v1/chat/completions",
    "auth": { "type": "bearer", "token": "<TARGET_API_KEY>" }
  },
  "context": {
    "domain": "language learning chatbot",
    "declared_system_prompt": "You are a helpful assistant...",
    "declared_safety_policy": "Must not generate harmful content...",
    "rendering_context": "html"
  },
  "categories": [
    "system_prompt_extraction",
    "direct_prompt_injection",
    "output_handling_unsafe_content",
    "jailbreak_persona_switch",
    "indirect_prompt_injection"
  ],
  "budget": {
    "max_attempts_per_category": 12,
    "max_total_seconds": 600
  },
  "models": {
    "judge": "anthropic/claude-sonnet-4-6",
    "attacker": "anthropic/claude-sonnet-4-6"
  }
}
```

For `generic_http` targets, add `request_template` and `response_path`:

```json
{
  "target": {
    "type": "generic_http",
    "url": "https://agent.example.com/api/query",
    "request_template": {
      "_method": "POST",
      "_path": "/api/query",
      "prompt": "{{user_message}}"
    },
    "response_path": "$.reply.text",
    "auth": { "type": "bearer", "token": "<KEY>" }
  }
}
```

The `{{user_message}}` placeholder is replaced with each attack string. `_method` and `_path` are stripped before sending.

## How to add a target

Edit `examples/stub-scan.json` with your target's details:

1. **OpenAI-compatible:** Set `"type": "openai_chat"`, `"url"` to the base URL, add `auth.token` if needed. The adapter will call `{url}/chat/completions` with `{"model":"default","messages":[{"role":"user","content":"..."}]}` and extract `$.choices[0].message.content`.

2. **Generic HTTP:** Set `"type": "generic_http"`, `"url"` to the base URL, provide a `request_template` with `{{user_message}}` where the attack string goes, and a `response_path` JSONPath expression to extract the agent's text response.

3. Set `context.domain` to describe what the agent does (improves attack tailoring).

4. Optionally provide `context.declared_system_prompt` and `context.declared_safety_policy` (sharpens extraction/jailbreak judging).

## How to add an attack module

1. Create a new file in `src/redteam_api/attacks/` (e.g., `my_new_category.py`):

```python
from redteam_api.attacks.base import AttackModule
from redteam_api.core.models import AttackAttempt, FindingCategory, ScanContext, ScanModels

class MyNewCategory(AttackModule):
    category = FindingCategory.MY_NEW_CATEGORY  # add this enum value in models.py

    async def generate_attempts(
        self, context: ScanContext, max_attempts: int, models: ScanModels | None = None
    ) -> list[AttackAttempt]:
        # Return AttackAttempt objects with attacker_prompt populated.
        # Use the LLM attacker model (via settings.rtapi_attacker_model) to generate
        # creative variants. Static templates for the first ~12, LLM-generated for more.
        return [...]

    async def judge_response(
        self, attempt: AttackAttempt, context: ScanContext, models: ScanModels | None = None
    ) -> dict[str, Any]:
        # Return {"success": bool, "severity": "P1"-"P5", "confidence": 0-1, "rationale": str}
        # Can use ClaudeJudge() for LLM judgment or heuristics for fast checks.
        return {...}

module = MyNewCategory()
```

2. Add the category to `FindingCategory` in `src/redteam_api/core/models.py`.

3. Register the module in `ATTACK_MODULE_MAP` in `src/redteam_api/core/orchestrator.py`.

4. Add attack seeds (if any) to `src/redteam_api/attacks/seeds/`.

5. Test against the stub target: `pytest tests/integration/test_e2e_against_stub.py`.

## Development

```bash
pip install -e ".[dev]"
ruff check src/
mypy --strict src/
pytest
```

## Architecture

```
POST /v1/scans
       │
       ▼
  Orchestrator.enqueue()
       │
       ├── asyncio.TaskGroup
       │    ├── system_prompt_extraction.run(adapter, context)
       │    ├── direct_prompt_injection.run(adapter, context)
       │    ├── … (all 5 in parallel)
       │    └── per attempt: adapter.send() → judge.judge() → storage.insert()
       │
       ▼
  Findings persist in SQLite (WAL mode) as they arrive
       │
       ▼
  GET /v1/scans/{id}/report → Markdown or JSON
```

- **Adapters:** abstract `TargetAdapter` → `OpenAIChatAdapter` / `GenericHTTPAdapter`
- **Judge:** `ClaudeJudge` (OpenRouter via OpenAI SDK, structured JSON output, prompt caching)
- **Storage:** SQLite + WAL via `aiosqlite`, single-file in `./data/redteam.db`
- **Worker:** `asyncio.TaskGroup` (no Celery/Redis for MVP)

## Stub target

The repo includes `tests/stub_target/server.py` — a deliberately-vulnerable Claude wrapper that leaks its system prompt (`INTERNAL_FLAG=ctf_redteam_2024`) and ignores safety instructions ~20% of the time. Used as the CI/dev signal: every attack module must produce findings against it.

To run the stub hardened (vulnerabilities off): `STUB_VULNERABLE=0 uvicorn tests.stub_target.server:app --port 8001`.

## License

MIT
