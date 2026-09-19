# RedVault — the project the Master AI Security course builds, breaks and defends

> This describes the real application in [`../src/`](../src/), read out of its code
> and [`../src/README.md`](../src/README.md) — not an imagined system. RedVault has
> been running in front of the cohort since session 1. There is no fictional client
> to invent: the client is the organisation that runs RedVault, and the course is
> about attacking and then hardening that organisation's assistant.

## At a glance

![RedVault — the project the Master AI Security course builds, breaks and defends](images/project_c1.png)

![RedVault — client, architecture, stack, end state and out-of-scope](images/project_g1.png)

## 1. The client

**RedVault Financial Services Pvt. Ltd.** — a mid-market fintech that runs an
internal, multi-tenant **enterprise AI assistant**, also called *RedVault*, for its
support, operations and sales teams. Each business unit is a tenant; the assistant
answers from that tenant's own knowledge base (onboarding guides, vendor lists,
runbooks) and can act on the user's behalf through a small set of tools — read a
record, delete a record, send an internal email, fetch a URL.

The constraint the client operates under is the one every real team has: they shipped
the assistant faster than they secured it. It grounds answers in retrieved documents,
it calls tools with real effect, and it trusts instructions equally whether they come
from the user, a retrieved document, an agent memory or a tool description. A seeded
internal marker, `INTERNAL_KEY`, sits in the system prompt as a stand-in for the kind
of secret such an assistant is routinely trusted with.

The ask brought to the course: **red-team RedVault to find what an attacker can make
it do, then re-architect it secure-by-design and prove every attack now fails** —
without moving off a $0, local, open-source stack that runs on a 16 GB laptop.

## 2. The system

RedVault is a small but complete enterprise AI assistant: a chat endpoint that grounds
its answers in a per-tenant document store and can take actions through a handful of
tools exposed over the Model Context Protocol. It ships in two postures — *vulnerable*
and *hardened* — that are the same code with the defences switched off or on, so the
same attack can be run against the weak build and then replayed against the strong one
to prove the control holds.

## 3. The architecture

Everything flows through **one function**, `redvault/pipeline.py::chat()`, which powers
both the FastAPI `/chat` endpoint and the attack scripts. Its numbered steps *are* the
control points:

    memory write -> input guard -> retrieval (RAG) -> naive model -> agent tool calls
      -> output guard + egress filter -> trace

- **Chat API & model router** — `redvault/api.py`, `redvault/llm.py`. FastAPI `/chat`;
  routes to a deterministic **stub** backend or a live **Ollama** model.
- **The naive model** — `redvault/intent.py`. Models a helpful assistant that obeys
  instructions from *any* channel (user text, retrieved doc, memory, tool description).
  **This is where the vulnerability lives, and it never changes with posture.**
- **RAG + data layer** — `redvault/db.py`, `redvault/embeddings.py`. SQLite + NumPy
  vector search by default; PostgreSQL 17 + pgvector on the live stack. Holds the
  per-tenant corpus.
- **Agent + MCP tools** — `redvault/mcp_tools.py` and the `redvault-mcp` container.
  Tool-calling agent over MCP: `read_record`, `delete_record`, `send_email`,
  `http_get`, `weather_lookup`. Tools are sandboxed fakes — nothing touches the real
  machine or network.
- **Defences (all off in vulnerable mode)** — `redvault/guards.py` (input/output
  moderation via Llama Guard / NeMo, egress filter), `redvault/labops.py` (ingest
  scanning), tenant scoping in `db.py`, and MCP manifest signing/allowlists in
  `mcp_tools.py`. Deliberately separated from `intent.py`: toggling one control flips
  one demo's outcome, which is the whole pedagogy.
- **Red-team harness** — `redteam/run.py` + `redteam/probes/` plus Promptfoo, garak and
  PyRIT; exit code = number of landed attacks. `attacks/` holds `extract_model.py` and
  `invert_embedding.py`.
- **Detection & telemetry** — `redvault/telemetry.py` writes one JSON trace per call to
  `data/traces/`; `detection/score_traces.py` scores them; Langfuse for tracing,
  Prometheus + Grafana for metrics and alerts.
- **Governance** — `redvault/governance.py`, `governance/control-map.md`,
  `governance/policy/mcp_calls.rego`; each control has a runnable check and an OPA gate.

Posture is `REDVAULT_MODE=vulnerable|hardened` merged with `data/state.json`, which the
`make enable-guard` / `harden-*` / `soften-*` / `contain` targets write via
`redvault/cli.py`. The API re-reads it every request, so a flag flips behaviour on a
running stack mid-demo.

## 4. The stack

Read from `src/requirements.txt`, `src/docker-compose.yml` and the brochure. All
free / open-source; a paid frontier model is never required.

- **Language / runtime:** Python 3.13.
- **API:** FastAPI 0.115.6, Uvicorn 0.34.0, Pydantic 2.10.4, httpx 0.28.1.
- **Data:** SQLite (default) or PostgreSQL 17 + pgvector 0.3.6 (`pgvector/pgvector:pg17`);
  psycopg 3.2.3; NumPy 2.2.1 for vector search.
- **Model runtime:** Ollama, running `llama3.1` and `llama-guard3` (`:1b` on 16 GB
  laptops). The default **stub** backend is deterministic, GPU-free and $0.
- **Agent protocol:** an MCP server exposing the agent's tools.
- **UI:** minimal chat UI (`src/ui/`), served via `nginx:1.27-alpine` on :5173; React 19
  + TypeScript per the brochure.
- **Offensive tooling:** Promptfoo, PyRIT, garak 0.15.1.
- **Defensive tooling:** Llama Guard (in Ollama), NeMo Guardrails, Guardrails AI.
- **Detection / ops:** Langfuse (self-hosted, SDK v4), Prometheus, Grafana, GitHub Actions.
- **Governance:** OWASP Threat Dragon, OPA/Rego.
- **Orchestration:** Docker / docker compose; GNU Make 4.3 (run from WSL on the trainer's
  Windows machine). Tests: pytest 8.3.4, pytest-asyncio 0.25.0.

A participant needs: a 16 GB laptop, Docker + Ollama, WSL (on Windows), Python 3.13, and
the repo. `make install && make seed && make test` proves the deterministic path with no
GPU.

## 5. The end state

When the last use case is done, the repository holds a RedVault that is
**vulnerable-by-switch and hardened-by-default, with every attack replayable both ways**:

- Every Module-2 attack (D4–D13) lands on `REDVAULT_MODE=vulnerable` and is blocked on
  `REDVAULT_MODE=hardened` — asserted by the 35-test suite and the `make redteam`
  scoreboard (RED on vulnerable, GREEN on hardened).
- Llama Guard and NeMo/Guardrails AI sit on the I/O path; the agent runs least-privilege
  with an approval gate, egress allowlist and step budget; RAG ingest is scanned and
  tenant-isolated; MCP manifests are signed, pinned and scanned.
- Langfuse traces every interaction, `detection/score_traces.py` scores attack
  signatures, and a Grafana alert fires on a replayed injection.
- The IR runbook can contain a tool, export a forensic timeline, and turn an incident
  into a regression probe.
- `governance/control-map.md` maps every control to NIST AI RMF, the GenAI Profile and
  EU AI Act obligations; `make verify-control` passes, `opa eval` returns `allow = true`
  on the hardened build, and `make compliance-report` generates a report from live
  evidence.
- A learner's fork carries the portfolio bundle: hardened app + red-team report +
  secure-by-design architecture + compliance report, with a green capstone Actions run.

Someone can look at the finished repo and check each of these is true.

## 6. Deliberately out of scope

- **A real frontier model and real user data.** Everything runs on local Ollama / the
  stub; tools are sandboxed fakes. This keeps the course $0 and safe and does not weaken
  the teaching, because the naive-model logic that decides whether an injection is
  *obeyed* is identical on stub and live — only the reasoning quality differs.
- **Production auth, secrets management and network hardening around the app.** RedVault
  demonstrates AI-specific controls, not general platform security; `INTERNAL_KEY` is a
  marker, not a managed credential. Real platform hardening is assumed as the layer this
  course sits on top of, not a lie about it.
- **Full multi-tenant scale, HA and cloud deployment.** One optional instructor-side GCP
  A100 VM covers only the GPU-heavy adversarial-ML variant; learners replicate at $0.
- **Fine-tuning / training a model.** The adversarial-ML work is extraction, membership
  inference and embedding inversion against the deployed system — not model training —
  which is the attack surface the client actually exposes.

## Names that must not change

Client **RedVault Financial Services Pvt. Ltd.**, system **RedVault**, and the stack
above are read by the demo builder and are fixed for the life of the course.
