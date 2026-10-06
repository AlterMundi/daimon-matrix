# Gemma 4 model, rules and local/offload antecedents

Research dated **2026-10-06**. The [contest analysis](CONTEST-ANALYSIS.md) supersedes consumer-GPU scenarios for current decisions. An RTX 5090 was an illustrative owner example; testing one, or testing 256K, is not a prerequisite for the competition design.

## Mandatory model

The permitted variant is `google/gemma-4-31B-it-qat-w4a16-ct`, approximately 30.7 billion parameters, **dense**, instruction-tuned and quantization-aware trained. Decoder weights use symmetric INT4, groups of 32, in compressed-tensors format; activations and embeddings remain 16-bit where specified. The family also contains a 26B A4B MoE, but that is not the allowed variant.

| Architecture/capability | Pinned model |
|---|---|
| Nominal model window | 262,144 tokens; competition config uses 32,768 |
| Decoder layers | 60: 50 local, 10 global, repeating 5:1 |
| Local attention window | 1,024 tokens |
| Attention heads | 32 |
| Local KV | 16 heads × dimension 256 |
| Global KV | 4 heads × dimension 512 |
| Hidden size / MLP | 5,376 / 21,504 |
| Vocabulary | 262,144 |
| Embeddings | Input/output tied by the inference engine |
| Cross-layer KV sharing | None: `num_kv_shared_layers = 0` |
| Input/output | Text, image and video frames; text generation; no audio in this 31B |
| Agent features | System role, configurable reasoning and tool calls |
| Languages | Pretraining covers more than 140 languages |
| License | Apache 2.0, as described by the model card |

Google recommends temperature 1, top-p 0.95 and top-k 64. Image token budgets include 70/140/280/560/1,120. The nominal window is not a guarantee of perfect retrieval: the model card reports 66.4% on an eight-needle MRCR v2 test at 128K; this is not a Kaggle or LoRA result. Tool-step reasoning and reasoning retained between user turns are handled differently by the chat format. Preserve the official template in a future experiment.

Sources: [Google model card](https://ai.google.dev/gemma/docs/core/model_card_4?hl=en), [QAT checkpoint](https://huggingface.co/google/gemma-4-31B-it-qat-w4a16-ct), [pinned configuration](https://huggingface.co/google/gemma-4-31B-it-qat-w4a16-ct/blob/52f3f65bc7a02d555763bc923bd1d9094898219d/config.json).

## Preserved one-device accounting

The safetensors file is 23,265,352,448 bytes, with 23,265,085,560 payload bytes. Each of its BF16 embedding/head matrices has shape 262,144 × 5,376. Tying saves 2.625 GiB; global K duplication adds about 0.0577 GiB. A one-device base estimate is **19.1000 GiB**, including **1.0724 GiB** vision/connector; text-only is **18.0276 GiB**. For TP placement use the newer contest calculation.

Ideal working KV for T tokens and b bytes per element:

```text
KV(T,b) = b × [10 × 2 × 4 × 512 × T
                + 50 × 2 × 16 × 256 × min(T,1024)]
```

| Tokens | BF16 KV GiB, aggregate | FP8 KV GiB, aggregate |
|---:|---:|---:|
| 8,192 | 1.40625 | 0.703125 |
| 16,384 | 2.03125 | 1.015625 |
| 32,768 | 3.28125 | 1.640625 |
| 65,536 | 5.78125 | 2.890625 |
| 131,072 | 10.78125 | 5.390625 |
| 262,144 | 20.78125 | 10.390625 |

K/V weights shared in global attention do not halve cache storage: K/V transformations differ. These are minimal working tensors with sliding-cache release, not full runtime allocation or an offloader's historical footprint. Source conditions and original illustrative scenarios are in [memory-results.json](2026-10-06/memory-results.json).

The earlier 5090 scenarios assumed nominal 32 GiB, a full r32 adapter per session and 2 GiB execution allowance. One 32K BF16 session gave 24.84 GiB, two 28.57, four 36.05; four 32K FP8 gave 29.49. A full 256K BF16 session exceeded capacity even without engine/adapter memory: base plus cache was 39.88 GiB. A 256K FP8 session with r32 and the assumed allowance gave **31.95 GiB**, too close to claim a guaranteed fit; utilization 0.90 would provide only 28.8 GiB under that nominal assumption.

These scenarios are tensor arithmetic, not our deployment measurements. They used unpinned main-branch vLLM sources and exclude extra fused buffers, page layout and runtime peaks; later competition analysis corrects those placement/allocation assumptions. [Original calculator](2026-10-06/calculate_memory.py), [NVIDIA 5090 specification](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/).

## Offload and durable memory

A controlled local deployment can investigate CPU tiers for idle prefix/session caches and a larger adapter catalog on RAM/disk, keeping a few active in VRAM. Cache policy matters: some offload configurations retain prompt blocks rather than all generated blocks. Loading or recomputing a cache costs transfer/prefill time.

An external hardware report used the same checkpoint on a 5090 with vLLM 0.24/0.25, FP8 cache, 64K context and a 48 GiB RAM tier. It reported faster warm resumption across five conversations totaling about 152K tokens. This is an author's report, not our benchmark, not the competition wheel, and not proof of five full 256K contexts. [Reported experiment](https://github.com/vllm-project/vllm/issues/48435).

An active context exceeding VRAM needs support for computation using transferred/CPU-resident attention state; idle-cache offload alone does not guarantee that. HeadInfer investigates head-level offload on other models, not a verified Gemma 4 31B+LoRA stack here. [HeadInfer paper](https://arxiv.org/abs/2502.12574). FP8 or selectively quantized global KV can reduce cache bytes, but compatibility/quality must be established and participant YAML does not expose it in this competition.

Durable conversation history can exceed the active prompt window: store records, retrieve relevant fragments and compact. KV is derived from model, adapter, tokens and execution settings; losing/invalidation of cache need not erase history. More RAM does not increase the model's nominal window or the evaluator's 32K window. Current contest scheduling and schema restrictions are detailed in [CONTEST-ANALYSIS.md](CONTEST-ANALYSIS.md).

## Competition rules and delivery

Different adapters per agent are explicitly allowed on the mandatory base. The published ADK schema supports sequential/parallel/loop agents and agents used as tools. Submission resources include prompts, skills, scripts and PEFT adapter configuration/safetensors; custom code executes through sandbox tools, not an unrestricted replacement for declarative agent construction. L4 sessions have Internet disabled. [Official competition overview](https://www.kaggle.com/competitions/gemma-4-developer-agent/overview).

The package limits include 3 GiB unpacked, 10,000 files, 500 agents, 1,000 skills, nesting depth 50 and up to 500 loop iterations. These are schema ceilings, not a feasible simultaneous deployment. Each skill has a 50 MiB ceiling. `max_output_tokens` and `thinking_budget` each have a 32,768 upper parameter bound, but generation/input still share the server window. Package defaults are 16,384 output and 4,096 reasoning. The server computes adapter count/rank from the submitted manifest. [Organizer wheelhouse](https://www.kaggle.com/datasets/metric/gemma-4-developer-agent-wheelhouse).

Archived data showed 129 development tasks from FastAPI, Rich, Requests and HTTPX, with approximately 120 hidden tasks and public/private leaderboard splits. Metric is the percentage of patched repositories passing validation tests. Time limit is aggregate, not a per-task allocation. [Competition data](https://www.kaggle.com/competitions/gemma-4-developer-agent/data).

External data must be equally accessible or satisfy the rules' reasonable-access/minimal-cost criteria. External preparation models/tools are subject to host-specific prohibitions and general obligations; no specific teacher/distillation setup was authorized by this research. Every inference agent uses the mandatory Gemma base. Do not presume private memory pools eligible, hand-label evaluation answers or share competition code/data privately outside the team. Winning delivery requires reproducible code/environment and an OSI-approved license permitting commercial use, subject to the rules. Teams may contain five people, with one daily submission and two selected final submissions. [Official rules](https://www.kaggle.com/competitions/gemma-4-developer-agent/rules).

As checked on 2026-10-06: optional paper deadline November 12, entry/team merger November 25, final submission December 2, at 23:59 UTC. Recheck before action. [Official timeline](https://www.kaggle.com/competitions/gemma-4-developer-agent/overview), [paper track](https://www.kaggle.com/competitions/gemma-4-developer-agent-paper).

The full gated HARNESS_README was not downloaded. Implementation conclusions reuse public organizer packages and the starter; verify the current full README before submitting. Competition entry and accepting its terms are separate actions from publication of this research.

## elRepo.io / RetroShare transport

The proposed reuse of elRepo.io concerns offline-tolerant transport and synchronization of durable records/resources across disconnected nodes. It does not add VRAM or extend a prompt. A design would need deduplication, receipts, reconciliation, retention and Matrix-authenticated authorship. Disconnected nodes retain data until a path is available; this does not imply autonomous replies or background activity without the applicable human authorization.

Old AlterMundi GitHub desktop/Android repositories are archived; relevant code was located on GitLab. The website domain redirected to unrelated material during research and is not a canonical project source. Repository links are the useful recovery points:

- [Archived desktop](https://github.com/AlterMundi/elRepo.io-desktop), [archived Android](https://github.com/AlterMundi/elRepo.io-android).
- [elrepo-lib](https://gitlab.com/elRepo.io/elrepo-lib), [Dart wrapper](https://gitlab.com/elRepo.io/retroshare-wrapper-dart).
- [RetroShare fork](https://gitlab.com/elRepo.io/RetroShare), [libretroshare](https://gitlab.com/elRepo.io/libretroshare), [Android](https://gitlab.com/elRepo.io/elRepo.io-android).
- [RetroShare documentation](https://retroshare.readthedocs.io/en/latest/).

Competition inference must operate without our hosts or mesh. A transport implementation remains separate future work; no revival/deployment was performed here.
