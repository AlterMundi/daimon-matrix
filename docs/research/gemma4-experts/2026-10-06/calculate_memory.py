#!/usr/bin/env python3
"""Tensor accounting, not a benchmark or a vLLM allocation guarantee.

Run alongside the saved public model config and safetensors header. No weights,
GPU, third-party dependencies, or credentials are required.
"""
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GIB = 1024**3
MIB = 1024**2
CONFIG = json.loads((ROOT / "model-config.json").read_text())
TEXT = CONFIG["text_config"]
HEADER = json.loads((ROOT / "safetensors-header.json").read_text())
TENSORS = {k: v for k, v in HEADER.items() if k != "__metadata__"}


def size(tensor):
    start, end = tensor["data_offsets"]
    return end - start


payload_bytes = sum(map(size, TENSORS.values()))
tied_head_bytes = size(TENSORS["lm_head.weight"])
vision_bytes = sum(size(v) for k, v in TENSORS.items()
                   if k.startswith(("model.vision_tower.", "model.embed_vision.")))
resident_payload_bytes = payload_bytes - tied_head_bytes
duplicated_global_k_bytes = sum(size(v) for k, v in TENSORS.items()
                                if k.startswith("model.language_model.layers.")
                                and ".self_attn.k_proj." in k
                                and TEXT["layer_types"][int(k.split(".")[3])] == "full_attention")
base_bytes = resident_payload_bytes + duplicated_global_k_bytes

# INT4 values are packed eight per I32 word along the input dimension.
linear_shapes = {}
for name, tensor in TENSORS.items():
    if name.startswith("model.language_model.layers.") and name.endswith(".weight_packed"):
        out_features, packed_in_features = tensor["shape"]
        linear_shapes[name] = (out_features, packed_in_features * 8)
attention_factor = sum(a + b for name, (a, b) in linear_shapes.items() if ".self_attn." in name)
all_decoder_factor = sum(a + b for a, b in linear_shapes.values())
layer_counts = Counter(TEXT["layer_types"])


def kv_bytes(tokens, bytes_per_element):
    full = layer_counts["full_attention"] * 2 * TEXT["num_global_key_value_heads"] * TEXT["global_head_dim"] * tokens
    local = layer_counts["sliding_attention"] * 2 * TEXT["num_key_value_heads"] * TEXT["head_dim"] * min(tokens, TEXT["sliding_window"])
    return (full + local) * bytes_per_element


contexts = [8192, 16384, 32768, 65536, 131072, 262144]
cache_rows = [{"tokens": n, "BF16_GiB": kv_bytes(n, 2) / GIB,
               "FP8_GiB": kv_bytes(n, 1) / GIB} for n in contexts]
lora_rows = [{"rank": rank,
              "attention_only_BF16_MiB": attention_factor * rank * 2 / MIB,
              "attention_and_MLP_BF16_MiB": all_decoder_factor * rank * 2 / MIB,
              "attention_and_MLP_BF16_GiB": all_decoder_factor * rank * 2 / GIB}
             for rank in (16, 32, 64, 128)]

# Illustrative envelope: independent contexts, one distinct r32 adapter per
# session, multimodal base weights, and an ASSUMED 2 GiB engine allowance.
# Actual allocation depends on vLLM version, fused adapter buffers, page layout,
# prefill/chunk sizes, graphs, media, fragmentation, and other GPU users.
scenarios = []
for tokens in (32768, 65536, 131072, 262144):
    for sessions in (1, 2, 4):
        for dtype, element_bytes in (("BF16", 2), ("FP8", 1)):
            total = base_bytes + sessions * (kv_bytes(tokens, element_bytes) + all_decoder_factor * 32 * 2) + 2 * GIB
            scenarios.append({"tokens_per_session": tokens, "sessions": sessions,
                              "cache_dtype": dtype, "illustrative_total_GiB": total / GIB,
                              "below_nominal_32_GiB": total <= 32 * GIB})

result = {
    "research_date": "2026-10-06",
    "checkpoint": "google/gemma-4-31B-it-qat-w4a16-ct",
    "checkpoint_revision": "52f3f65bc7a02d555763bc923bd1d9094898219d",
    "sources": [
        "https://huggingface.co/google/gemma-4-31B-it-qat-w4a16-ct/blob/52f3f65bc7a02d555763bc923bd1d9094898219d/config.json",
        "https://huggingface.co/google/gemma-4-31B-it-qat-w4a16-ct/tree/52f3f65bc7a02d555763bc923bd1d9094898219d",
        "https://github.com/vllm-project/vllm/blob/main/vllm/model_executor/models/gemma4.py",
        "https://github.com/vllm-project/vllm/blob/main/vllm/model_executor/models/interfaces.py",
        "https://docs.vllm.ai/en/latest/design/hybrid_kv_cache_manager/",
        "https://www.kaggle.com/datasets/metric/gemma-4-developer-agent-wheelhouse",
    ],
    "assumptions": {
        "nominal_gpu_GiB": 32,
        "engine_allowance_GiB_for_scenarios": 2,
        "cache": "Ideal working K/V tensors: full layers retain the full sequence; sliding layers retain the last 1024 tokens; K and V are separate.",
        "excluded": "Runtime repacking, padding, cache scales, graph/prefill peaks, extra fused LoRA buffers and reserved CUDA/display memory are not measured.",
        "adapters": "BF16 A/B weights on decoder attention and optionally MLP only; no embeddings, vision or modules_to_save; rank does not change the KV dimensions.",
        "training": "All results concern inference. Gradients, activations and optimizer states for training are excluded.",
        "offload": "Working KV size is not necessarily the RAM tier footprint: an offloader may retain additional historical blocks.",
    },
    "architecture": {"layer_counts": dict(layer_counts), "local_window": TEXT["sliding_window"],
                     "context_limit": TEXT["max_position_embeddings"], "decoder_linear_matrices": len(linear_shapes)},
    "weights": {
        "checkpoint_tensor_payload_GiB": payload_bytes / GIB,
        "tied_head_saving_GiB": tied_head_bytes / GIB,
        "resident_tied_tensor_payload_GiB": resident_payload_bytes / GIB,
        "global_K_projection_duplication_GiB": duplicated_global_k_bytes / GIB,
        "base_tensor_estimate_GiB": base_bytes / GIB,
        "vision_and_projection_GiB": vision_bytes / GIB,
        "text_only_base_tensor_estimate_GiB": (base_bytes - vision_bytes) / GIB,
    },
    "cache_by_context": cache_rows,
    "lora_by_rank": lora_rows,
    "illustrative_scenarios": scenarios,
}
(ROOT / "memory-results.json").write_text(json.dumps(result, indent=2) + "\n")
for name, rows in (("cache-by-context", cache_rows), ("lora-by-rank", lora_rows), ("illustrative-scenarios", scenarios)):
    with (ROOT / f"{name}.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
print(json.dumps({k: result[k] for k in ("architecture", "weights", "cache_by_context", "lora_by_rank")}, indent=2))
