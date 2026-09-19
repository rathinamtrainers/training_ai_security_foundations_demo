# RedVault — use-case backlog (redesign from session 6 onward)

**Scope of this backlog.** Sessions 1–5 are taught and stay exactly as delivered; they
are not re-planned or re-taught here. The lab is up (session 1), the OWASP LLM Top-10 /
ATLAS / STRIDE threat model exists (sessions 2–3), the AI-BOM exists (session 4), and a
red-team baseline is established (session 5: a Promptfoo baseline of ~21% attack success,
garak installed but not yet run, PyRIT positioned only). **Use case 1 begins there.**

**Ceiling.** 11 sittings remain (sessions 6–16) at 2 live hours each = **22.0 live hours
= 1320 live minutes**, not 32. Five of the sixteen sittings are spent. This is the only
number the ledger below sums against.

**This is a backlog, not a schedule.** No use case is assigned to a session. The trainer
covers as much as the room takes each sitting and carries the rest forward. The estimates
exist only so the ledger can catch a backlog that does not fit — and it does not quite
fit; see the ledger.

## At a glance

![RedVault use-case backlog — client, end state, pipeline and the 13 use cases](images/usecases_c1.png)

![RedVault use-case backlog — attack, defend, operate arc with the time ledger](images/usecases_g1.png)

## 1. The arc

The remaining course is three movements against one unchanging app. **Attack** (UC1–UC5):
take RedVault's vulnerable posture and prove, end to end, what an attacker can make it do
— leak a secret, clone the model, invert an embedding, drive the agent into destructive
and lateral action, poison the supply chain and the corpus — then freeze those attacks
into a one-command, CI-gated red-team scoreboard that is RED. **Defend** (UC6–UC9): switch
on one control at a time — I/O guardrails, a least-privilege sandboxed agent, RAG/data and
supply-chain hardening — replaying each attack against its control until the scoreboard
goes GREEN. **Operate & prove** (UC10–UC13): make the hardened system observable (tracing,
detection, alerting), rehearse incident response on a live attack, map every control to
NIST AI RMF / GenAI Profile / EU AI Act as policy-as-code, and hand the whole thing over
in a graded live red-vs-blue capstone. UC11 comes after UC10 because you cannot do
trace-based forensics before there are traces; the defences (UC6–UC9) come before detection
(UC10) because there is nothing worth alerting on until the loud attacks are quiet.

## 2. The use-case table

| # | Use case | Status | Delivers | Teaches | Est. min |
|---|---|---|---|---|---|
| 1 | Leak the secret with a prompt injection | Planned | Direct + indirect + jailbreak attacks land: `INTERNAL_KEY` leaks in chat and via a poisoned RAG doc, garak quantifies the jailbreak rate | LLM01 direct/indirect injection, LLM07 system-prompt leakage, LLM02 multi-hop exfiltration, jailbreak taxonomy + filter fragility; MITRE ATLAS technique IDs on the live attacks; STRIDE-for-LLM naming; OWASP MCP Top-10 walk; OWASP Agentic Security Initiative | 130 |
| 2 | Steal the model and read a stored embedding | Planned | `stolen.jsonl` clones RedVault's behaviour; private text reconstructed from a pgvector row | LLM10 model extraction/theft (AML.T0024), behavioral cloning, membership inference, LLM08 embedding inversion, vector-store privacy, unbounded-consumption framing | 100 |
| 3 | Make the agent act — excessive agency & memory poisoning | Planned | The agent runs a destructive tool from injected text; a planted memory drives multi-tool lateral movement | LLM06 excessive agency, confused-deputy problem, memory poisoning & lateral movement (Agentic Security Initiative) | 95 |
| 4 | Poison the tools and the corpus | Planned | A poisoned MCP tool *description* hijacks the agent on load; one poisoned RAG doc steers all answers | MCP03 tool poisoning (CVE-2025-54136 / -54135), LLM04 data/model poisoning, LLM09 misinformation, LLM01 via retrieved content | 95 |
| 5 | Freeze the attacks into a red CI scoreboard | Planned | `make redteam` runs Promptfoo + garak + PyRIT as one command, a custom RedVault probe FAILs, GitHub Actions goes red and blocks merge | Suite assembly, custom probe authoring, regression suites, CI security gate, the red/green scoreboard | 110 |
| 6 | Guardrails I — moderate the I/O path | Planned | Llama Guard refuses the direct injection; re-run garak flips the prompt-injection probes green | Input/output classification, Llama Guard 3 (& :1b), defense-in-depth on the I/O path, before/after measurement; fixes LLM01/LLM07 | 100 |
| 7 | Guardrails II — programmable rails & output validation | Planned | NeMo Colang rails + Guardrails AI validators added; before/after garak shows jailbreak rate drop sharply | NeMo input/dialog/retrieval/execution/output rails, Guardrails AI validators, rails vs classifiers, custom rail authoring, residual risk; fixes LLM05 | 110 |
| 8 | Secure-by-design agent | Planned | Destructive tool now needs approval; egress allowlist + step budget block lateral movement (shown in MCP logs) | Least-privilege tools, human-in-the-loop approval gates, sandboxing, egress allowlists, step-budget caps; fixes LLM06 + lateral movement | 100 |
| 9 | Harden RAG, the data layer & the supply chain — go green | Planned | Poisoned doc rejected at ingest, cross-tenant vector access denied, poisoned tool fails signature check; hardened `make redteam` is GREEN | Ingest scanning, pgvector tenant isolation, MCP signing/pinning, description scanning, server allowlist; fixes LLM08 + indirect LLM01 + MCP03 | 110 |
| 10 | See the attacks — detection engineering | Planned | Langfuse shows a replayed attack end-to-end; trace scoring populates a metric; a Grafana alert fires on an injection | LLM observability, Langfuse SDK v4, end-to-end traces, trace scoring for attack signatures, Prometheus metric + Grafana alert, NIST *Measure* | 110 |
| 11 | Respond to an AI incident | Planned | The IR runbook run live: contain the offending tool, export a forensic timeline, turn the incident into a regression probe | IR lifecycle for AI (detect->triage->contain->forensics->close-loop), containment, trace forensics, regression-probe loop, NIST *Manage* | 100 |
| 12 | Prove it — governance & compliance-as-code | Planned | Controls mapped to NIST AI RMF / GenAI Profile / EU AI Act; `verify-control` passes, `opa eval` true on hardened, compliance report generated | NIST AI RMF Govern/Map/Measure/Manage + GenAI Profile, EU AI Act obligations + 2026 timeline, ISO/IEC 42001, control mapping, OPA/Rego policy-as-code, auto compliance report | 110 |
| 13 | Defend under live fire — graded capstone | Planned | RedVault survives a rotated attack set with the scoreboard green; the full portfolio bundle merged to `main` | Red-vs-blue methodology, rotated attack sets, defending under live attack, the scoreboard as shared truth, portfolio-bundle assembly, assessment rubric | 120 |

## 3. The use cases

### UC1 — Leak the secret with a prompt injection
**Objective.** Prove RedVault will leak its system prompt and `INTERNAL_KEY` to a direct
injection, exfiltrate the secret indirectly through a poisoned RAG document, and quantify
its jailbreak rate. **Before:** vulnerable RedVault, baseline established, no injection
performed live end to end. **After:** posture unchanged (still vulnerable) but three attack
classes are demonstrated and evidenced; this is the sitting where the four owed framework
aspects (ATLAS IDs, STRIDE-for-LLM, MCP Top-10, Agentic Security Initiative) land *on* the
attacks. **Demonstrated live:** D4 (direct leak + French round-trip filter-fragility
variant), D5 (`make poison-doc` then an innocent summarise request appends the secret), D6
(garak `dan,encoding,latentinjection` sweep read aloud). **By the end a participant can**
leak a system prompt directly, exfiltrate a secret via a poisoned doc, and read a garak
jailbreak rate, labelling each attack with its ATLAS technique ID.

### UC2 — Steal the model and read a stored embedding
**Objective.** Clone RedVault's behaviour by querying it and reconstruct private text from a
stored vector. **Before:** injection fluency, vulnerable build. **After:** posture unchanged;
two adversarial-ML attacks evidenced, motivating the tenant-isolation and embedding defences
of UC9. **Demonstrated live:** D7 (`extract_model.py --queries 200` -> `stolen.jsonl` +
behavioral-similarity estimate; `--offline` for the deterministic replica), D8
(`invert_embedding.py --row 1/42` prints reconstructed private text). **By the end a
participant can** run an extraction query loop, reason about membership inference, and invert
an embedding, explaining why vector stores are sensitive.

### UC3 — Make the agent act: excessive agency & memory poisoning
**Objective.** Drive the agent to run a destructive tool from injected text, and plant a
false memory that drives multi-tool lateral movement. **Before:** vulnerable agent, no
approval gate. **After:** posture unchanged; the agentic attack surface is demonstrated,
setting up UC8's secure-by-design agent. **Demonstrated live:** D9 (injected "delete record
7 now" -> `delete_record(7)` with no approval, shown in `make mcp-logs`; reset `make seed`),
D11 (plant an `OVERRIDE-9` memory, then in a new session read a file and email it — two tools
chained; reset `make reset-memory`). **By the end a participant can** explain excessive
agency and the confused-deputy problem and demonstrate memory-driven lateral movement.

### UC4 — Poison the tools and the corpus
**Objective.** Hijack the agent by poisoning a tool *description*, and bias every answer by
poisoning one RAG document. **Before:** vulnerable build, unsigned MCP manifest. **After:**
posture unchanged; the supply-chain and data-poisoning surface is demonstrated, setting up
UC9. This use case also carries the one owed walk of the OWASP MCP Top-10 against RedVault's
MCP server if UC1 did not reach it. **Demonstrated live:** D10 (`make poison-tool` — the
agent attempts the attacker `http_get` from the loaded description alone; reset
`make reset-tools`), D12 (`make poison-doc` with `rag-steer.md` — every answer recommends
`ACME-EVIL`; reset `make seed`). **By the end a participant can** poison an MCP tool
description and a RAG corpus and explain MCP03 and LLM04/LLM09. *Split note:* UC3 and UC4 are
the one densest offensive session (four demos) split into two finishable use cases; if room
is tight they can be run back-to-back in one sitting.

### UC5 — Freeze the attacks into a red CI scoreboard
**Objective.** Assemble Promptfoo + garak + PyRIT into one command, author a custom
RedVault-specific probe, and wire a CI gate that fails the build on any landed attack.
**Before:** attacks run ad hoc. **After:** posture unchanged, but the attacks are now a
repeatable, CI-gated suite — `make redteam` RED, Actions red, merge blocked. This scoreboard
is the instrument every defence use case turns green. **Demonstrated live:** D13
(`make redteam`; show and re-run with `redteam/probes/redvault_secret_leak.py`; `cat` the
workflow, push a branch, show Actions go red). **By the end a participant can** run a
one-command red team, add a custom probe, and read a red CI gate.

### UC6 — Guardrails I: moderate the I/O path
**Objective.** Add Llama Guard as an input/output classifier and prove the direct injection
is refused. **Before:** vulnerable I/O path. **After:** RedVault gains its first defence —
`make enable-guard GUARD=llamaguard` on; direct injection refused, garak prompt-injection
probes flip to pass. Fixes LLM01/LLM07 on the I/O path. **Demonstrated live:** D14 (enable
Llama Guard, replay D4 -> refused, re-probe -> green). **By the end a participant can** add
Llama Guard 3 (or `:1b`), place a classifier on the I/O path, and measure the control
before/after.

### UC7 — Guardrails II: programmable rails & output validation
**Objective.** Layer NeMo Colang rails and Guardrails AI output validators on top of the
classifier. **Before:** classifier-only defence. **After:** RedVault has programmable
input/dialog/retrieval/execution/output rails and structured-output validation
(`make enable-guard GUARD=nemo`); before/after garak shows the jailbreak rate drop sharply.
Fixes LLM05. **Demonstrated live:** D15 (enable rails, before/after garak). **By the end a
participant can** author a custom rail, contrast rails with classifiers, and reason about
residual risk.

### UC8 — Secure-by-design agent
**Objective.** Re-architect the agent least-privilege with an approval gate, egress
allowlist and step budget. **Before:** an agent that runs any tool on injected intent.
**After:** `make harden-agent` on — the destructive tool needs approval, lateral movement is
blocked in the MCP logs. Fixes LLM06 and the UC3 lateral-movement chain. **Demonstrated
live:** D16 (replay D9/D11 against the hardened agent -> approval required, egress denied).
**By the end a participant can** design a least-privilege sandboxed agent with human-in-the-
loop gates, egress allowlists and step-budget caps.

### UC9 — Harden RAG, the data layer & the supply chain: go green
**Objective.** Scan ingest, isolate tenants, and sign/scan MCP manifests — then run the full
suite green. **Before:** vulnerable RAG and unsigned tools. **After:** `make harden-rag` and
`make harden-supplychain` on — poisoned docs rejected at ingest, cross-tenant vector access
denied, poisoned/unsigned tools fail the signature check; `REDVAULT_MODE=hardened make
redteam` is GREEN and the CI gate would pass. This is the green-scoreboard milestone. Fixes
LLM08, indirect LLM01, MCP03. **Demonstrated live:** D17 (harden-rag, replay D5 + D8), D18
(harden-supplychain, replay D10, then full suite green). **By the end a participant can**
harden the RAG/data layer and the MCP supply chain and prove the replayed attacks are blocked.

### UC10 — See the attacks: detection engineering
**Objective.** Instrument RedVault with Langfuse, view an attack end-to-end, score traces for
attack signatures, and raise a Grafana alert. **Before:** hardened but blind. **After:**
RedVault is observed — Langfuse traces every call, `score_traces.py` populates
`redvault_attack_score`, a Grafana alert fires on a replayed injection. Carries NIST *Measure*.
**Demonstrated live:** D19 (wire Langfuse SDK v4, replay an attack, open the trace), D20
(score traces, watch the Grafana alert fire). **By the end a participant can** instrument an
app with Langfuse, score traces, and wire an alert on an attack signature.

### UC11 — Respond to an AI incident
**Objective.** Run the IR runbook on a live attack — detect, triage, contain, do trace
forensics, close the loop. **Before:** observed but no rehearsed response. **After:** RedVault
gains a working IR loop — `make contain TOOL=http_get` quarantines the tool, a timeline is
exported from the trace, `make add-probe` turns the incident into a regression probe that the
suite then covers. Carries NIST *Manage*. **Demonstrated live:** D21 (trigger an attack, run
detect->triage->contain->forensics->close-loop; reset `make uncontain`). **By the end a
participant can** run one full AI IR cycle and convert an incident into a permanent regression
test.

### UC12 — Prove it: governance & compliance-as-code
**Objective.** Map RedVault's controls to NIST AI RMF, the GenAI Profile and EU AI Act
obligations, verify a control with the harness, enforce policy-as-code with OPA/Rego, and
auto-generate a compliance report. **Before:** controls work but are unmapped and
unattested. **After:** `governance/control-map.md` maps every control to all governance
frameworks; `make verify-control` passes; `opa eval` returns `allow = true` on hardened
evidence (`false` on vulnerable); `make compliance-report` produces a report from live
evidence. **Demonstrated live:** D22 (walk control-map, `verify-control`), D23 (`cat` the
Rego, `make evidence` + `opa eval`, `make compliance-report`). **By the end a participant
can** map controls to NIST/EU AI Act/ISO 42001 and enforce and evidence them as policy-as-code.

### UC13 — Defend under live fire: graded capstone
**Objective.** Defend a fresh RedVault against a rotated, live attack set and assemble the
full portfolio deliverable bundle. **Before:** a hardened, observed, governed RedVault.
**After:** the terminal deliverable — `REDVAULT_MODE=hardened make redteam-capstone` stays
green under attacks not seen verbatim in the labs; the bundle (hardened app + red-team report
+ secure-by-design architecture + compliance report) is merged to `main`. This is the
hand-over, which for this subject is itself the lesson. **Demonstrated live:** rotated D-set
red-vs-blue rounds with `make redteam` and the Langfuse UI as the shared scoreboard. **By the
end a participant can** defend RedVault end-to-end under live attack and present a
certification-grade portfolio piece.

## 4. Coverage check

Module 1 (sessions 1–4) is taught and excluded. This backlog carries Modules 2–4 and the
remaining framework aspects owed from sessions 1–5.

| Brochure aspect | Carried by |
|---|---|
| **Module 2 — Offensive: attacking AI systems** | UC1–UC5 |
| Prompt injection — direct, indirect, multi-hop exfiltration (LLM01/LLM02/LLM07) | UC1 |
| Jailbreak taxonomy & filter fragility | UC1 |
| Adversarial ML — model extraction, membership inference, embedding inversion (LLM08/LLM10) | UC2 |
| Agentic exploitation — excessive agency, confused-deputy, memory poisoning (LLM06) | UC3 |
| AI supply-chain attacks — poisoned MCP servers, tool-description injection, lateral movement (MCP03) | UC3 (lateral movement), UC4 (tool poisoning) |
| RAG poisoning / misinformation (LLM04/LLM09) | UC4 |
| Custom automated red-team harness + CI gate | UC5 |
| **Module 3 — Defensive: hardening & architecture** | UC6–UC9 |
| Guardrails / I-O defenses with Llama Guard | UC6 |
| Guardrails with NeMo Guardrails + Guardrails AI | UC7 |
| Least-privilege, sandboxed, egress-controlled agents | UC8 |
| Secure RAG & data layer; harden supply chain — MCP signing, scanning | UC9 |
| Every Module-2 attack replayed and blocked; scoreboard green | UC6–UC9 (green at UC9) |
| **Module 4 — Detection, operations, governance & capstone** | UC10–UC13 |
| Detection engineering (Langfuse, Prometheus, Grafana); NIST *Measure* | UC10 |
| AI incident response; NIST *Manage* | UC11 |
| Compliance-as-code (OPA/Rego); NIST AI RMF Govern/Map; GenAI Profile | UC12 |
| EU AI Act + ISO/IEC 42001 mapping | UC12 |
| Graded live red-vs-blue capstone + portfolio bundle | UC13 |
| **Frameworks — provable coverage map** | |
| OWASP LLM Top-10 v2.0 (every category attacked then defended) | Attacked UC1–UC4; defended UC6–UC9 |
| MITRE ATLAS technique IDs on each attack | UC1 (owed since S2, lands here), UC2 (AML.T0024) |
| STRIDE-for-LLM vocabulary named against the attack surface | UC1 (owed since S2) |
| OWASP MCP Top-10 walked against RedVault | UC1/UC4 |
| OWASP Agentic Security Initiative | UC1 (memory poisoning framing continues in UC3) |
| NIST AI RMF (Govern/Map/Measure/Manage) + GenAI Profile | Measure UC10, Manage UC11, Govern/Map UC12 |
| EU AI Act + ISO/IEC 42001 as policy-as-code | UC12 |
| **Project deliverable — hardened, monitored app + red-team report + secure-by-design architecture + compliance report** | UC13 (assembled), built across UC5/UC9/UC10/UC12 |

Nothing in the brochure's Module 2–4 coverage is dropped. Module 1 aspects (AI attack
surface, threat modeling, AI-BOM, red-team lab setup) are covered by the taught sessions 1–5
and are deliberately not repeated here.

## 5. The time ledger

| Bucket | Minutes |
|---|---|
| UC1–UC5 (attack) | 130 + 100 + 95 + 95 + 110 = 530 |
| UC6–UC9 (defend) | 100 + 110 + 100 + 110 = 420 |
| UC10–UC13 (operate & prove) | 110 + 100 + 110 + 120 = 440 |
| **Total** | **1390** |
| **Ceiling (11 sittings x 120 min)** | **1320** |
| **Over by** | **70 min** |

**It does not fit, and it fits worse than these numbers show.** The 1390 is teach-plus-demo
only; it excludes per-sitting recap, Q&A and wrap, which the delivered sessions budget at
~35 min each — real live capacity for new material is well under 1320. The existing plan
already carried 17 rows against 16 recorded sittings and overran by design, and this backlog
inherits that debt: it packs the same twelve sessions' content (S6–S17) into eleven remaining
sittings.

**What I would cut, in order, rather than shrink estimates:**
1. **Merge UC3 + UC4 into one dense agentic sitting** (as session 8 originally was) — saves
   the duplicated recap/context (~30–40 min) and is the honest split-back if the room is
   moving slowly. This alone roughly closes the gap.
2. **Drop the PyRIT depth in UC5** to positioning-only (Promptfoo + garak carry the harness);
   PyRIT has been positioning-only since session 5 already. Saves ~20 min.
3. **Fold UC11 (incident response) into UC10's detection sitting** as a single
   detect->contain narrative if still over; it costs the least because both run off the same
   Langfuse traces.
I would **not** cut UC13 (the graded capstone is the sold terminal deliverable) or UC9 (the
green-scoreboard milestone that makes the whole "attack then defend the same app" promise true).

## 6. What the trainer must decide

- **The overrun is real (see §5).** Decide before the redesign starts whether to merge
  UC3+UC4 and trim UC5's PyRIT, or to accept carrying the capstone into a 12th sitting — the
  plan already broke 16 into 17, so a 17th sitting overall is consistent with what happened.
- **Assumption: session 5's carried debt lands in UC1.** garak-run, honest report-reading and
  the four owed framework aspects (ATLAS IDs, STRIDE-for-LLM, MCP Top-10, Agentic Security
  Initiative) are folded into UC1/UC4 rather than given their own use case, matching the
  session plan's stated intent to teach them *inside* D4/D5.
- **Assumption: the live stack (Ollama/Docker/pgvector) is available for the demos that need
  it** (D5, D8, D9–D12, D14–D23); where it is not, the runbook fallbacks (cached reports,
  `--offline`, captured screenshots) stand in, exactly as the session plan already specifies.
- **Assumption: no new RedVault code is required.** Every use case maps to demos D4–D23 and
  Make targets that already exist in `src/`; this backlog re-plans delivery, not the app.
- **Membership inference (UC2) stays a reasoned/stretch item**, not a built demo, because
  `src/` ships extraction and inversion scripts but no membership-inference demo — consistent
  with the session plan treating it as a stretch.
