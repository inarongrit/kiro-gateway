# Strands Decider 2B — CPU guardrail evaluation (PoC notes)

Evaluates `StrandsAgents/strands-decider-2B-hobson-v19` (via PyPI `strands-decider`,
pinned `0.1.0`) as an **optional local yes/no policy layer** for the Kiro gateway PoC,
running CPU-only on this server (4 vCPU, no GPU).

## Authenticity (checked before install)
- PyPI project `strands-decider` v0.1.0. Its long-description badges/links point only to
  `github.com/strands-labs/strands-decider` (home_page/project_urls metadata fields are
  null, but the rendered description links are exclusively that repo). Matches the blog
  https://strandsagents.com/blog/introducing-strands-decider/ and the repo README.
  → Not a typosquat. Safe to install.

## What the model does
Decision ("System One") model: a Qwen3.5-2B torso with the LM head replaced by a tiny
pointer head. Three question types; we use **noul** (yes/no), which returns `P(yes)`.
Multiple questions about one `state` are answered in a **single forward pass** (the
state is encoded once, each question's short suffix is run against the shared KV cache).

## Environment (reproducible)
```bash
uv venv "$KIROCREW_SCRATCH/decider-venv" --python 3.12
# CPU-only torch FIRST (avoids multi-GB CUDA wheels):
uv pip install --python "$KIROCREW_SCRATCH/decider-venv/bin/python" \
    torch==2.7.1 --index-url https://download.pytorch.org/whl/cpu
# then the package, keeping torch CPU:
uv pip install --python "$KIROCREW_SCRATCH/decider-venv/bin/python" \
    strands-decider==0.1.0 \
    --index-url https://pypi.org/simple \
    --extra-index-url https://download.pytorch.org/whl/cpu
```
Pinned at eval time: `strands-decider==0.1.0`, `torch==2.7.1+cpu`,
`transformers==5.18.0`. Model weights (~4.4 GB, 37 files) cache under `$HF_HOME`.

## bfloat16 note
The task asked to load in bf16 if the library allows. It does **not** on CPU: the engine
deliberately **upcasts the torso to fp32** on CPU (`_upcast_torso_for_cpu` in
`infer.py`) because bf16 CPU kernels are slower than fp32. So the torso runs fp32
(~confirmed `torch.float32`), costing memory (~7 GiB torso) rather than saving it.

## Run
```bash
export HF_HOME="$KIROCREW_SCRATCH/hf"
export TOKENIZERS_PARALLELISM=false
cd docs/evaluation
"$KIROCREW_SCRATCH/decider-venv/bin/python" decider_eval.py \
    --threads 4 --testset testset.jsonl --out results-decider.json
```
Flags: `--threads N` → `torch.set_num_threads(N)`; `--limit N` for a quick smoke run.

The script loads the model once, warms up on item 0 (untimed), then times each item
(wall clock, one at a time). Each item asks all 4 questions (`q_pii`, `q_secret`,
`q_attack`, `q_exfil`) in ONE `engine.ask()` call. Verdict = **block if any question's
`P(yes)` >= threshold**; metrics reported at 0.5 / 0.7 / 0.9.

## Memory safety
The runs were wrapped in a shell watchdog that kills the eval if `MemAvailable` drops
below 2 GB. Peak RSS observed ~9.5 GB (fp32 torso) against ~11 GB available — it fit but
with little margin. Per-item memory is flat after load (model loaded once).

## Kernel fallback (performance caveat)
`causal_conv1d` and `flash-linear-attention` are **not installed** (no CUDA/Triton on
this box), so the torso's Gated DeltaNet layers run their **reference PyTorch kernels** —
"correct but much slower". This dominates latency: ~8 s per 4-question item on CPU.
A GPU build would be far faster (blog cites ~115 ms/question on an RTX 3090).

## Outputs
- `results-decider.json` — versions, peak RSS, load time, latency stats (overall /
  per-lang / per-question), per-item probs+verdicts, per-threshold TP/FP/FN/TN +
  precision/recall overall/per-lang/per-kind, FP/FN id lists.
- `decider_eval.py` — the script.
- `decider-notes.md` — this file.

All testset data is synthetic/fake.
