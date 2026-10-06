# Continue the Gemma 4 Developer Agent investigation

Updated **2026-10-06**. This is the public continuation entry for CompAII's research into a shared Gemma 4 base, specialized LoRA experts, persistent conversations and Matrix coordination. It can be continued from any host, including `compaii.codex@daimonmatrix`; **nothing here requires the original workstation to stay online**.

## Read these first

1. [CONTEST-ANALYSIS.md](CONTEST-ANALYSIS.md): current four-L4/32K calculations, margins, permitted features and experiment design.
2. [BACKGROUND.md](BACKGROUND.md): model capabilities, rules, earlier consumer-GPU calculations, offload and elRepo.io research.
3. [contest-results.json](contest-4l4-32k/contest-results.json) and [calculate_contest.py](contest-4l4-32k/calculate_contest.py): exact inputs, assumptions, sensitivity and executable accounting.
4. [evidence-manifest.json](evidence-manifest.json) and [official source hashes](contest-4l4-32k/official-vllm-source-manifest.json): source integrity and recovery information.

## Owner direction

The latest sizing instruction is to use **Google/Kaggle's actual environment and effective competition context**, not the illustrative RTX 5090 or the model's full 256K capacity. Keep the existing research and evidence; do not restart it. The owner subsequently requested a public repository handoff so the conversation and work can continue on daimonmatrix without depending on the workstation.

The owner also asked whether a larger expert roster can rotate idle sessions through RAM/SSD. **Yes for retained histories and bounded active calls; KV offload is a separate engine feature.** Four is a starting scenario, not a hard expert limit. The current submission schema does not expose KV offload or a participant-configured adapter swap catalog. Details are preserved in the analysis.

## Findings already established

- Official environment: four L4s, advertised 24 GB each, TP=4, BF16 activations/KV, utilization 0.90, **32,768 total tokens per request**. Every agent uses `gemma-4-31b-it-qat-w4a16-ct`.
- Base tensor estimate with vision: **5.5812 GiB/GPU**. Decoder/embeddings are sharded; vision/norms are replicated. Do not simply divide one-device weights by four.
- A 32K context: approximately **0.8234 GiB/GPU in paged decode**, **1.2140 GiB/GPU in a per-request 2K-prefill bound** using source-default blocks. Without hybrid KV management, **6.875 GiB/GPU**.
- Complete r32 adapter: **0.4561 GiB on disk**, **0.2161 GiB per slot per GPU** in default decoder buffers. The largest configured rank applies to every reserved slot. Attention-only files can save package size without reducing deployment-default buffer allocation.
- Four r32 slots plus four 32K contexts: **15.30 GiB/GPU** in a conservative envelope, including **4 GiB assumed engine reserve**. With **hypothetical 22 GiB CUDA-visible capacity** and utilization 0.90, headroom is **4.50 GiB/GPU**. These are calculations, not GPU measurements.
- Four complete r32 files total **1.8243 GiB**, leaving **1.1757 GiB** under the unpacked 3 GiB limit. Six r32 or three r64 total 2.7365 GiB. The final zip must include header/config/skills bytes too.
- Generation shares the 32K window with inputs. A 16K generation cap leaves at most 16K input before template overhead. Suggested initial input 12–20K, generation cap 4–8K, reasoning 1–2K within generation; validate rather than treat as a new requirement.
- Store history as text/records and retrieve needed pieces. More roles can run a few at a time, sharing adapters where useful. Stored history, active KV and adapter residency are different quantities.
- Shared-base batching is supported, but experts share compute. Harness selection does not make the dense model a neural MoE. Matrix retains identity/continuity; expert roles do not automatically create beings or embodiments.

## Evidence state

The model configuration/header is pinned to HF revision `52f3f65bc7a02d555763bc923bd1d9094898219d`. Calculators require only these included public metadata files and Python stdlib.

Official overview/rules and starter version 2 were reread on 2026-10-06. Wheelhouse **v28** contains `adk_submission 0.2.12`, `swegemma 0.2.7`, `adk_eval_core 0.1.0` and patched **vLLM 0.19.1**. Twenty-one selected vLLM Python members were extracted with range requests and individually hashed. The organizer enables wrapper LoRA and corrects duplicate module registration; stock alone is not the full implementation.

Source-derived OpenAI-server defaults on L4 are 2,048 batched tokens and maximum 256 sequences. The source's default local block size is 16; actual backend overrides remain unmeasured, and 16/32/64/128 sensitivity is included. Effective CUDA capacity, CPU/RAM and actual engine overhead are unknown. Whole binary wheels, weights, browser captures, credentials and private memory are not needed for this public handoff.

The archived consumer-GPU calculator is unchanged. Its main-branch vLLM references were not pinned to a commit; use it for antecedents, not competition runtime truth. No adapter training, L4 inference, enrollment or competition submission has been performed. No long-running experiment is waiting to be resumed.

## Next executable work

Reproduce the current accounting from a fresh clone:

```bash
python3 docs/research/gemma4-experts/contest-4l4-32k/calculate_contest.py
```

Then prepare an experiment using competition L4s/current wheelhouse. The server host can prepare artifacts and analyze results without local GPU access; actual L4 measurements require Kaggle execution. Start with the base/starter before eligible trained/selected adapters exist.

1. Record actual GPU/CUDA totals/free memory, CPU/RAM, resolved flags, wheel identity, model/graph allocation, KV pool/block sizes and prefill defaults.
2. Verify adapter application and global shared K/V behavior, request routing and prefix-cache separation.
3. Measure 1/2/4 active requests inside 32K: VRAM peak, first-token latency and aggregate throughput. Test eight only if preceding evidence supports it.
4. Compare base, prompt-only specialists and LoRA specialists on the same development subset and equal total time, using test pass rate and context/tool/generation timings.
5. Validate final unpacked package, current full harness README and rule/evaluator changes before entering/submitting. Entry acceptance and publication of a competition submission were not authorized merely by requesting this investigation.

Suggested first package: coordinator and two to four specialists for navigation, editing, tests and review; four complete r32 adapters; portable sandbox skills and reproducible technical knowledge. The unpacked 3 GiB limit and shared 12-hour budget matter more than idle text-history storage. Do not assume private memory eligibility, host network access or Codex/Hermes tool compatibility.

Related tracking: this publication is #264; competition evidence can inform #252, whose compute-credit and convergence-pilot criteria remain separate. This handoff does not resume or declare complete another CompAII rollout goal. The [functional foundation](../../foundation/daimon-matrix.md) governs naming, scopes and ontology.
