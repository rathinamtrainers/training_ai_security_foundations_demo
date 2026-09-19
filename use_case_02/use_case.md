# UC2 — Steal the model and read a stored embedding

> Master AI Security (Foundations) · Use case 2 of the RedVault backlog
> (`use_case_plan.md`, row 2). Second movement-**Attack** use case against the one
> unchanging app in [`../../src/`](../../src/). The code that runs it lives in
> [`demo/`](demo/); this document is written from what that code does against a
> seeded RedVault, not from the plan alone.

## 1. The client scenario, and why it matters

RedVault Financial Services runs an internal, multi-tenant AI assistant. Each
business unit is a tenant; the assistant answers from that tenant's own private
knowledge base, stored as vectors in a pgvector (or, on a laptop, SQLite) store, and
it is reachable on an internal `/chat` endpoint that nobody thought to rate-limit or
meter.

Two things the client believes are safe are not:

- **The endpoint is "just a chat box."** But an uncapped, unmetered inference API is a
  model you can *copy*. An attacker who queries it enough times walks away with a
  dataset that reproduces its behaviour — no weights stolen, no breach logged.
- **The vector store is "just anonymised numbers."** But an embedding is not a
  one-way hash. Given the model's vocabulary, the salient private words peel straight
  back out of the vector. A vector-store leak is a *text* leak — and in a vulnerable,
  un-isolated store, one tenant can reach another tenant's rows.

This is the sitting where the room learns why the UC9 defences (tenant isolation,
embedding privacy) and LLM10 rate/budget controls exist: because these two attacks
land cleanly first.

## 2. What this use case delivers

Row 2's **Delivers** line: *"`stolen.jsonl` clones RedVault's behaviour; private text
reconstructed from a pgvector row."* Expanded, the `demo/` folder delivers:

- **`stolen.jsonl`** — a harvest of query/response pairs from the live `/chat`
  endpoint, written by `d7_extract_model.py`, plus a **behavioural-similarity
  estimate** that quantifies how reproducibly the target answers (how cloneable it
  is). On the deterministic stub this is 100% — maximally extractable.
- **Reconstructed private text from a stored vector** — `d8_invert_embedding.py`
  pulls one row's stored `embedding` blob from RedVault's real store and inverts it
  back to its salient words using the model's own maths, *without reading the text
  column to do so*. It also inverts a **cross-tenant** row, showing the vulnerable
  store hands over data across tenant boundaries.
- **A membership-inference illustration** — `membership_inference.py`, a stretch item
  (the backlog keeps MI reasoned, not a built shadow-model attack): it decides whether
  a specific text is indexed from the embedder's confidence gap.
- **One acceptance run** — `uc2_steal_and_read.py` chains all three and prints a
  single `UC2 RESULT: PASS/PARTIAL/FAIL` line, the verifier's success criterion.
- **`FRAMEWORKS.md`** — the OWASP/ATLAS/STRIDE labels mapped onto each real attack.

## 3. The system and mechanism it exercises

Everything targets the real RedVault in `src/`, read out of its code:

- **Extraction** speaks the exact `/chat` contract in `src/redvault/api.py`
  (`ChatRequest{message, session, tenant}` in, `{answer, leaked_secret, retrieved,
  labels, ...}` out). The harvest loop only needs `message` in and `answer` out.
  When the API is down, `--offline` drives `src/redvault/pipeline.py::chat()`
  in-process — the same code the endpoint runs, labelled as a fallback, never faked.
- **Inversion and membership inference** go at the store *behind* `/chat`. They open
  the SQLite file RedVault writes (`src/data/redvault.db`, schema in
  `src/redvault/db.py`: `documents(id, tenant, title, text, embedding BLOB)`)
  **read-only** (`mode=ro`), so a demo can never mutate the app. On the Docker stack
  the same rows live in Postgres + pgvector; the float32 blob is identical, so the
  attack is backend-agnostic.
- **`embed_mini.py`** is a byte-for-byte replica of `src/redvault/embeddings.py`
  (same `DIM=256`, same SHA-256 token seed, same greedy `invert`). It is a copy, not
  an import, because the room clones this folder alone — but it must match the app's
  maths exactly or the inversion would not line up with the real stored blobs. It
  does, so the reconstruction is genuine.

The seeded corpus (`src/redvault/labops.py::seed`) makes the row ids stable: docs
1–4 are the `acme` seed articles, **doc 5 is the `globex` confidential-pricing row**
used for the cross-tenant demonstration; `records` are seeded for other use cases.

## 4. The attacks, in order, with framework labels

1. **Model extraction / behavioural cloning** — `d7_extract_model.py`. Harvests
   query/response pairs into `stolen.jsonl` and reports behavioural similarity.
   *OWASP LLM10 Unbounded Consumption (the uncapped endpoint is the enabler) + model
   theft; MITRE ATLAS **AML.T0024** Exfiltration via ML Inference API; STRIDE
   Information Disclosure (+ Denial of Service for the unbounded loop).*
2. **Membership inference (stretch)** — `membership_inference.py`. Uses the
   confidence gap between a seeded member phrase and an invented non-member to decide
   what was indexed. *ATLAS **AML.T0024**; STRIDE Information Disclosure.*
3. **Embedding inversion** — `d8_invert_embedding.py`. Reconstructs private words
   from a stored vector alone, including the cross-tenant `globex` row.
   *OWASP **LLM08** Vector & Embedding Weaknesses; ATLAS **AML.T0024**; STRIDE
   Information Disclosure.* The cross-tenant reach is the gap UC9 `make harden-rag`
   (tenant isolation) later closes.

## 5. Posture — before and after

- **Before:** vulnerable RedVault, store seeded. No rate limiting on `/chat`, no
  tenant isolation on the vector store.
- **After:** posture **unchanged** — still vulnerable. This use case *evidences* two
  adversarial-ML attacks; it applies no defence. It motivates UC9 (tenant isolation,
  embedding privacy) and the LLM10 rate/budget controls. Run against a `hardened`
  build the cross-tenant inversion is denied — that is UC9's teaching point, not this
  one, and the acceptance line reports `FAIL` there by design.

## 6. How to run it end to end

First, from `src/` in a WSL shell, install and seed the shared app so the store
exists (`make seed` writes `src/data/redvault.db`; docs 1-4 are `acme`, doc 5 is
the `globex` row). Optionally bring the live stack up for the HTTP extraction path
— it is not required, because extraction falls back to RedVault's own in-process
pipeline:

```bash
make install && make seed
REDVAULT_MODE=vulnerable docker compose up -d      # optional; enables the live HTTP harvest
```

Then, from `demo/`, the simplest run uses RedVault's own venv, so the offline
extraction fallback can import the app and NumPy is already present:

```bash
../../../src/.venv/bin/python uc2_steal_and_read.py
```

With the stack up you can instead use a bare venv (`pip install -r requirements.txt`,
just NumPy) and let extraction harvest over HTTP:

```bash
python uc2_steal_and_read.py
```

Expected final line:

```
UC2 RESULT: PASS - cloned RedVault into stolen.jsonl (similarity 100%) and reconstructed private text from stored vectors, including a cross-tenant row.
```

PASS is gated on the two headline deliverables — `stolen.jsonl` cloning RedVault and
private text reconstructed from the cross-tenant stored vector. Own-tenant inversion
of the longer `acme` row is shown for teaching but not required: on a long document
the shared greedy-recovery threshold surfaces the salient/repeated tokens rather than
every word. Individual attacks (`d7_extract_model.py`, `d8_invert_embedding.py`,
`membership_inference.py`) are runnable on their own — see [`demo/README.md`](demo/README.md).
