# Gemma 4 experts on the competition's four L4 GPUs

**Finding, 2026-10-06:** one shared Gemma 4 base, request-specific LoRA adapters and several active conversations fit the published Google/Kaggle execution environment by tensor accounting. Four complete rank-32 adapters and four 32K contexts leave substantial room in a conservative envelope. Quality and time-to-solution need a GPU experiment; neither CPU offload nor a consumer GPU is a prerequisite for this design.

These are reproducible calculations, **not a measured Kaggle allocation or throughput benchmark**. No weights were downloaded, adapters trained, GPU quota consumed, competition rules accepted or submission made. The official overview, rules, starter notebook version 2 and wheelhouse were checked on 2026-10-06. The wheelhouse remains version 28, updated 2026-09-30. Selected Python sources were extracted from its patched vLLM wheel through HTTP Range; their hashes and a recovery script are included.

## Execution envelope

| Item | Published configuration |
|---|---|
| Hardware | Four NVIDIA L4 GPUs, advertised 24 GB each |
| Base | `gemma-4-31b-it-qat-w4a16-ct` for every agent/subagent |
| Distribution | Tensor parallelism 4 in the official starter |
| Effective context | **32,768 total tokens per request** |
| Weights / activations / KV | QAT INT4 / BF16 / BF16 with published defaults |
| GPU utilization | 0.90 of CUDA-visible memory on each GPU |
| Submission | Declarative `agent.yaml`, prompts, skills and optional adapters; **3 GiB unpacked** |
| Evaluation time | 12 hours across tasks, including setup, excluding subsequent patch validation |
| Networking | Internet disabled for L4 sessions |

Hardware, model selection and evaluation conditions are documented in the [official overview](https://www.kaggle.com/competitions/gemma-4-developer-agent/overview). TP, context, dtype and utilization come from the [official starter, version 2](https://www.kaggle.com/code/ryanholbrook/getting-started-gemma-4-developer-agent). Package/generation limits were also read in `swegemma/config.py` from the [organizer wheelhouse](https://www.kaggle.com/datasets/metric/gemma-4-developer-agent-wheelhouse).

All four GPUs participate in each TP request. There is no one-expert-per-GPU assignment, and the advertised 96 GB is not one contiguous GPU. Batched requests share compute and TP communication. NVIDIA specifies 24 GB and PCIe Gen4 x16 for L4; that does not establish the actual interconnect latency or CUDA-visible capacity. [NVIDIA L4 specifications](https://www.nvidia.com/en-us/data-center/l4/).

Effective CPU/RAM limits of the Kaggle container were not established from the official sources consulted. Kaggle links to [Google Compute L4 documentation](https://cloud.google.com/compute/docs/gpus#l4-gpus), but VM specifications do not prove the container's allocation. Capture CPU/RAM and GPU totals in the first experiment. This unknown does not alter the GPU accounting or expose offload configuration to submissions.

## Weight placement

The calculation reuses the archived configuration and 2,009 tensor entries of `google/gemma-4-31B-it-qat-w4a16-ct`, revision `52f3f65bc7a02d555763bc923bd1d9094898219d`. Quantized groups are 32; embeddings and several other tensors remain BF16. [Pinned configuration](https://huggingface.co/google/gemma-4-31B-it-qat-w4a16-ct/blob/52f3f65bc7a02d555763bc923bd1d9094898219d/config.json).

The checkpoint payload is 21.6673 GiB. It contains an `lm_head` copy which vLLM ties to input embeddings, saving 2.625 GiB. Global K projections are loaded into V slots too, adding about 0.0577 GiB. Decoder matrices and vocabulary embeddings are TP-sharded. The Transformers vision tower, its `ReplicatedLinear` connector, and small decoder norms are replicated.

| Resident tensor estimate | GiB/GPU |
|---|---:|
| Sharded text | 4.5063 |
| Replicated text norms/scalars | 0.0025 |
| Replicated vision/connector | 1.0724 |
| **Base with vision, matching the example** | **5.5812** |
| Text-only alternative, not assumed for judging | 4.5088 |

Replication makes aggregate weights about 22.325 GiB across four GPUs, versus about 19.10 GiB on one device. Dividing the one-device estimate by four understates per-GPU residency. Tiny checkpoint shape metadata is retained in this accounting although it need not remain in CUDA. Kernel repacking, extra padding, RoPE buffers, activations, graphs and other workspaces are not measured; they are budgeted separately.

The organizer wheel confirms tying with LoRA enabled. [Stock Gemma 4 v0.19.1](https://github.com/vllm-project/vllm/blob/v0.19.1/vllm/model_executor/models/gemma4.py) is a useful reference, but the official wheel additionally enables LoRA on the multimodal wrapper and avoids duplicate module registration. Its extracted sources, rather than stock alone, govern this analysis.

## Conversation cache

There are 50 sliding-attention layers with a 1,024-token window and 10 full-attention layers. Per GPU, local layers have four KV heads of dimension 256; global layers have one of dimension 512. K/V are stored separately despite shared global projection weights. For T tokens and BF16:

```text
Ideal KV/GPU = 2 bytes × 2 (K and V) ×
  [10 × 1 × 512 × T + 50 × 4 × 256 × min(T, 1024)]
```

| Total tokens | Ideal KV GiB/GPU | Paged decode estimate | Per-request prefill bound, 2K chunk |
|---:|---:|---:|---:|
| 8,192 | 0.3516 | 0.3546 | 0.7452 |
| 16,384 | 0.5078 | 0.5109 | 0.9015 |
| 24,576 | 0.6641 | 0.6671 | 1.0577 |
| **32,768** | **0.8203** | **0.8234** | **1.2140** |

Prefill includes newly scheduled tokens plus the recent local window. Paged values use source-default local blocks of 16; uniform-page adjustment doubles global block size to 32. No backend-selected L4 block size was captured. Sensitivity for local blocks 32/64/128 is included: the 32K prefill bound rises from 1.2140 to at most 1.2354 GiB/GPU in those cases.

The wheel's OpenAI-server defaults on L4 are **2,048 batched tokens** and **256 maximum sequences**. A sequence limit is not evidence that 256 full contexts fit. The hybrid KV manager releases local-window blocks. LoRA does not automatically disable it in this version; the official builder sets neither a disabling flag nor an offload connector.

Without hybrid management, a 32K context needs **6.875 GiB/GPU** of KV. Capture resolved flags and memory logs in the real experiment. [Hybrid manager design](https://docs.vllm.ai/en/v0.19.1/design/hybrid_kv_cache_manager/), [KV specifications](https://github.com/vllm-project/vllm/blob/v0.19.1/vllm/v1/kv_cache_interface.py), [server defaults](https://github.com/vllm-project/vllm/blob/v0.19.1/vllm/engine/arg_utils.py).

## Adapter files versus GPU buffers

Independent BF16 attention/MLP matrices in the checkpoint require `2 × rank × 7,651,840` bytes per complete decoder adapter, plus headers/config. Attention-only uses factor 2,813,440. These estimates exclude embeddings, vision and `modules_to_save`.

Default TP LoRA is only partially sharded: column A is replicated and B sharded, with complementary placement for row projections. Fused QKV and gate/up allocate per-slice buffers, including a global V slot absent as an independent checkpoint matrix. Decoder buffers require **3,624,960 elements × maximum rank × adapter slots per GPU**.

The deployment filter is unrestricted, so all supported decoder linear modules get buffers. An attention-only file saves submission space but does not necessarily lower VRAM reservation. Tower/connector LoRA is disabled by default; Gemma 4 declares no embedding adapter modules in this wheel.

| Rank | Complete file GiB | Attention-only GiB | Buffers per slot GiB/GPU | Complete files with 0.25 GiB reserved for resources |
|---:|---:|---:|---:|---:|
| 16 | 0.2280 | 0.0838 | 0.1080 | 12 |
| 32 | 0.4561 | 0.1677 | 0.2161 | **6** |
| 64 | 0.9122 | 0.3354 | 0.4321 | **3** |
| 128 | 1.8243 | 0.6708 | 0.8643 | 1 |

These are payload ceilings, not validation of a constructed zip. Six complete r32 adapters occupy 2.7365 GiB, leaving about 269.8 MiB for everything else. Four occupy 1.8243 GiB and leave about 1,203.9 MiB. Each skill has a separate 50 MiB limit in the published package.

The server derives `max_loras` from the adapter manifest count and rounds maximum rank to a supported bucket. Eight slots/rank 128 in the starter are not fixed competition caps. **Every slot uses the largest configured rank**: one r128 plus three r16 creates four r128 slots. Different prompt roles can share one adapter.

Attention-only files with 0.25 GiB reserved allow payload counts of 32/16/8/4 at ranks 16/32/64/128. Quality relative to attention+MLP is unknown; deployment-default full decoder buffers still apply. [LoRA configuration](https://github.com/vllm-project/vllm/blob/v0.19.1/vllm/config/lora.py), [fused buffers](https://github.com/vllm-project/vllm/blob/v0.19.1/vllm/lora/layers/column_parallel_linear.py), [deployment target filtering](https://github.com/vllm-project/vllm/blob/v0.19.1/vllm/lora/model_manager.py).

## A conservative envelope

Assume **22 GiB CUDA-visible capacity per L4**, deliberately conservative and hypothetical, not a measurement or conversion of advertised 24 GB. At utilization 0.90, budget is 19.8 GiB/GPU. Keep vision, four r32 slots and **4 GiB/GPU of assumed additional engine memory**. The latter is unmeasured. Results also cover 22.5/24 GiB capacity and 2/4 GiB reserves.

| Independent 32K conversations | Decode working total GiB/GPU | Conservative prefill total GiB/GPU | Headroom under 19.8 GiB |
|---:|---:|---:|---:|
| 1 | 11.27 | 11.66 | 8.14 |
| 2 | 12.09 | 12.87 | 6.93 |
| **4** | **13.74** | **15.30** | **4.50** |
| 8 | 17.03 | 20.16 | −0.36 |

The conservative prefill column gives each conversation an entire 2K chunk simultaneously, overestimating a real multi-request peak because the scheduler shares 2K across its batch. Eight failing this pessimistic envelope does not prove eight impossible. Four leave room even under it. Blocks of 128 lower four-request headroom to about 4.41 GiB. More concurrency requires measurements; decode-only cache capacity does not establish throughput.

These are working-use envelopes, not expected `nvidia-smi` readings. vLLM normally reserves residual memory for its KV pool and may show nearly 90% usage with one request. Real model/graphs/media/workspace overhead beyond the assumed reserve changes headroom.

## More than four experts, RAM and SSD

**Four experts is an initial experiment, not a limit.** Distinguish three quantities: available expert roles/adapters, active inference requests and retained conversation history. A larger roster can run a few experts at a time. Additional complete adapters are constrained first by package size; prompt-defined roles may share adapters.

Conversation text, tool records, summaries and recovered knowledge can live in RAM or sandbox files while an expert is idle. Resuming constructs its prompt and runs prefill, unless the engine retained a matching prefix. A logical session does not guarantee a permanent VRAM allocation between API calls. Idle histories do not need to retain all their KV to remain durable.

KV offload is a different feature: storing computed tensors in CPU RAM, or an SSD-backed tier supported by a cache backend, can avoid some recomputation. It requires explicit engine/backend support, compatible hybrid attention and LoRA handling, and measured transfer costs. RAM is typically the faster tier; SSD offers more capacity with extra latency. Offloading idle caches does not guarantee that an active context too large for VRAM can be computed, nor does it extend the request's configured window.

**The current competition submission schema does not expose these server settings.** The builder reserves GPU adapter slots for the full manifest; it does not implement participant-selected rotation of a huge CPU/SSD adapter catalog. For the competition, use a larger logical roster with bounded active calls and stored text, rather than assuming a configurable KV swap service. Outside judging, a controlled vLLM deployment can investigate tiered caches and adapter rotation. [LoRA serving](https://docs.vllm.ai/en/v0.19.1/features/lora/), [v0.19.1 cache/offload configuration](https://github.com/vllm-project/vllm/blob/v0.19.1/vllm/config/cache.py).

## Context and time budgets

The 32K window includes instructions, history, tool results, reasoning and answer. Generation is not additional space beyond it. Do not count reasoning again when it is already included in the endpoint's generated-token cap.

| Requested generation cap | Theoretical input ceiling before template overhead |
|---:|---:|
| 16,384, package default | 16,384 |
| 8,192 | 24,576 |
| 4,096 | 28,672 |

The starter compacts at 14,336 tokens, interval 15, overlap 2, retention 5. This example does not guarantee that arbitrary tool output fits or that a submission can replace evaluator-wide policies. Per-agent generation, prompts and `include_contents` are exposed; individual parameter limits do not authorize exceeding combined context.

Initial choices to evaluate: inputs normally 12–20K, generation caps 4–8K and reasoning 1–2K inside that generation budget. Preserve history as files and retrieve relevant fragments/resummaries. Bound tool output so a log does not exhaust the prompt. These are design recommendations, not new acceptance rules.

Archived official data described approximately 120 hidden tasks. Twelve hours divided by 120 is about six minutes per task on average before setup, not an enforced per-task timeout. Experts share that global budget. Repeated prefill, reasoning, tests and review calls consume time; no own tokens/s result exists, and theoretical TFLOPS is not a substitute. [Evaluation data](https://www.kaggle.com/competitions/gemma-4-developer-agent/data).

## Admissible design and Matrix meaning

Start with a coordinator and two to four task-selected specialists: navigation/diagnosis, editing, tests and review. A coordinator using the unadapted base is an option. ADK supports sequential, parallel, loop and tool-invoked agents. Parallel independent exploration can help; coordinate writes to avoid losing patches on a shared checkout.

Candidate package: four complete r32 adapters, leaving 1.176 GiB for configuration and resources. Portable ADK skills can provide symbol navigation, test selection, trace reading and patch checks using sandbox tools. Codex/Hermes skills may depend on unavailable tools and require adaptation. Shared technical knowledge must satisfy external-data accessibility and licensing; private memory pools are not presumed eligible. [Rules on external data and reproducible winning delivery](https://www.kaggle.com/competitions/gemma-4-developer-agent/rules).

Matrix owns identity, authorship and continuity. An expert role or selected LoRA does not by itself create a new being, embodiment or relationship. The harness selects calls/adapters; the mandatory 31B remains a dense network, not a token-routed neural MoE. See the [functional foundation](../../foundation/daimon-matrix.md) before changing naming or ontology.

The zip schema does not expose FP8 KV, longer context, offload, `fully_sharded_loras` or deployment target-module filtering. `extra_args` exists in the organizer's server library but is not a supported participant `agent.yaml` field. This design uses published defaults. elRepo.io/RetroShare remains relevant to future local/offline-tolerant transport, not GPU capacity; judging must work without an external mesh.

## Next experiment and decisions it resolves

Use competition L4s and the current wheelhouse. Adapters do not yet exist in this research archive. First profile the base/starter, then add trained or selected eligible adapters; random LoRA is not evidence of specialization.

1. Capture GPU/CUDA totals/free memory, CPU/RAM, wheel identity, resolved flags, KV blocks, model/graph memory, available cache and prefill defaults. Establish the actual envelope and hybrid-manager status.
2. Verify adapter deltas reach intended modules, including global shared K/V projections, selection per request and prefix-cache separation. Allocated buffers alone do not prove correct deltas.
3. Measure 1/2/4 requests with 8/16/24K prompts and reserved generation that keeps totals inside 32K. Record peak VRAM, first-token latency and aggregate throughput. Consider eight only if measurements justify it.
4. Compare base, prompt-only specialists and LoRA specialists on the same development subset with equal total time. Record test passes, context failures, generated/prefill tokens and tool time. More calls alone are not improved resolution.
5. Validate actual unpacked zip size, the full current harness README and evaluator/rule changes before entering or submitting. No enrollment or submission happened during this investigation.

No general architecture search needs restarting. Unpublished runtime values and empirical quality/throughput remain specific open items.

## Reproduction and evidence

Run `python3 contest-4l4-32k/calculate_contest.py` from this directory. Inputs are included public configuration/header metadata; no GPU, model weights, secrets or dependencies beyond stdlib are needed. Outputs: [JSON](contest-4l4-32k/contest-results.json), [cache CSV](contest-4l4-32k/cache-by-context.csv), [adapter CSV](contest-4l4-32k/lora-by-rank.csv), [scenario CSV](contest-4l4-32k/scenarios.csv).

The [official-source manifest](contest-4l4-32k/official-vllm-source-manifest.json) records selected member hashes. [extract_official_wheel.py](contest-4l4-32k/extract_official_wheel.py) recovers those Python members from the pinned public wheel without retrieving weights or binary libraries; it requires Internet. Sources are not vendored in this publication. The archived whole vLLM wheel was not downloaded or hashed: selected ZIP members were CRC-checked by Python and SHA256-recorded.

[BACKGROUND.md](BACKGROUND.md) preserves model capabilities, rules, consumer-GPU/offload antecedents and transport research. [HANDOFF.md](HANDOFF.md) is the continuation entry; [evidence-manifest.json](evidence-manifest.json) covers the public artifact files. Original consumer-GPU calculations remain reproducible in `2026-10-06/`; their assumptions do not govern contest calculations.
