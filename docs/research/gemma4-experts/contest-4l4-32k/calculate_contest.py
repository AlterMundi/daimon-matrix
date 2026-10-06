#!/usr/bin/env python3
"""Contest tensor accounting from archived metadata and organizer vLLM sources.

No model weights, GPU, installed vLLM or external dependencies required.
Values describe tensors and hypothetical envelopes, not measured throughput.
"""
import csv
import json
import math
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PREVIOUS = ROOT.parent / '2026-10-06'
GIB = 1024**3
MIB = 1024**2
TP = 4
ELEMENT_BYTES = 2
MAX_CONTEXT = 32768
PACKAGE_LIMIT = 3 * GIB


def tensor_bytes(tensor):
    return tensor['data_offsets'][1] - tensor['data_offsets'][0]


def cdiv(a, b):
    return (a + b - 1) // b


def main():
    text = json.loads((PREVIOUS / 'model-config.json').read_text())['text_config']
    header = json.loads((PREVIOUS / 'safetensors-header.json').read_text())
    tensors = {k: v for k, v in header.items() if k != '__metadata__'}
    counts = Counter(text['layer_types'])
    local_layers = counts['sliding_attention']
    global_layers = counts['full_attention']
    assert (local_layers, global_layers, text['sliding_window']) == (50, 10, 1024)

    payload = sum(map(tensor_bytes, tensors.values()))
    head = tensor_bytes(tensors['lm_head.weight'])
    vision = sum(tensor_bytes(v) for k, v in tensors.items()
                 if k.startswith(('model.vision_tower.', 'model.embed_vision.')))
    # Norms and layer scalars are replicated. Packed matrices, scale matrices
    # and vocab weights are sharded; tiny shape metadata is included in payload
    # even though it need not remain on the GPU after loading.
    replicated_text = sum(tensor_bytes(v) for k, v in tensors.items()
                          if k.startswith('model.language_model.')
                          and not any(s in k for s in
                                      ('q_proj.', 'k_proj.', 'v_proj.', 'o_proj.',
                                       'gate_proj.', 'up_proj.', 'down_proj.', 'embed_tokens.')))
    duplicate_k = sum(tensor_bytes(v) for k, v in tensors.items()
                      if k.startswith('model.language_model.layers.') and '.self_attn.k_proj.' in k
                      and text['layer_types'][int(k.split('.')[3])] == 'full_attention')
    sharded_text = payload - head - vision - replicated_text + duplicate_k
    base_per_gpu = sharded_text / TP + replicated_text + vision

    shapes = {k: (v['shape'][0], v['shape'][1] * 8)
              for k, v in tensors.items()
              if k.startswith('model.language_model.layers.') and k.endswith('.weight_packed')}
    file_attention_factor = sum(a + b for k, (a, b) in shapes.items() if '.self_attn.' in k)
    file_all_factor = sum(a + b for a, b in shapes.values())

    # Default vLLM deployment filter is None, so all supported decoder linear
    # modules get buffers, even for attention-only adapter files. Embeddings
    # and lm_head are not declared in Gemma4.embedding_modules; tower LoRA is
    # disabled by default. Fused QKV includes a global V slot absent on disk.
    hidden = text['hidden_size']
    mlp = text['intermediate_size']
    buffer_factor = 0
    for kind in text['layer_types']:
        dim = text['head_dim'] if kind == 'sliding_attention' else text['global_head_dim']
        kv_heads = text['num_key_value_heads'] if kind == 'sliding_attention' else text['num_global_key_value_heads']
        q_out, kv_out = text['num_attention_heads'] * dim, kv_heads * dim
        assert q_out % TP == kv_out % TP == mlp % TP == 0
        qkv = 3 * hidden + (q_out + 2 * kv_out) // TP
        output = q_out // TP + hidden
        gate_up = 2 * (hidden + mlp // TP)
        down = mlp // TP + hidden
        buffer_factor += qkv + output + gate_up + down
    assert (file_attention_factor, file_all_factor, buffer_factor) == (2813440, 7651840, 3624960)

    # Block size 16 is the source default, NOT a captured GPU runtime value.
    # Uniform-page adjustment doubles the global block size because its KV
    # per token is half the local layer's. Backend overrides remain a runtime
    # measurement item. Table includes sensitivity to other page sizes.
    local_token_bytes = ELEMENT_BYTES * 2 * (text['num_key_value_heads'] // TP) * text['head_dim']
    global_token_bytes = ELEMENT_BYTES * 2 * (text['num_global_key_value_heads'] // TP) * text['global_head_dim']
    assert local_token_bytes == 2 * global_token_bytes

    def ideal_kv(tokens):
        return (global_layers * global_token_bytes * tokens
                + local_layers * local_token_bytes * min(tokens, text['sliding_window']))

    def paged_kv(tokens, scheduled_tokens=1, local_block=16):
        global_block = local_block * local_token_bytes // global_token_bytes
        full = global_layers * cdiv(tokens, global_block) * global_block * global_token_bytes
        local_tokens = min(tokens, text['sliding_window'] - 1 + scheduled_tokens)
        sliding = local_layers * (cdiv(local_tokens, local_block) + 1) * local_block * local_token_bytes
        return full + sliding

    # Source-derived OpenAI server defaults on L4: 2048 batched tokens, 256
    # sequences, normal balanced mode; participant YAML exposes neither knob.
    # Single-request conservative profile bound mirrors SlidingWindowSpec.
    cache_rows = []
    for tokens in (8192, 16384, 24576, MAX_CONTEXT):
        cache_rows.append({
            'total_tokens': tokens,
            'ideal_BF16_GiB_all_GPUs': ideal_kv(tokens) * TP / GIB,
            'ideal_BF16_GiB_per_GPU': ideal_kv(tokens) / GIB,
            'paged_decode_GiB_per_GPU_block16': paged_kv(tokens) / GIB,
            'paged_prefill_GiB_per_GPU_chunk2048_block16': paged_kv(tokens, 2048) / GIB,
            'paged_prefill_GiB_per_GPU_chunk8192_block16_sensitivity': paged_kv(tokens, 8192) / GIB,
            'no_hybrid_GiB_per_GPU': tokens * (global_layers * global_token_bytes + local_layers * local_token_bytes) / GIB,
        })
    assert ideal_kv(MAX_CONTEXT) * TP / GIB == 3.28125

    lora_rows = []
    for rank in (16, 32, 64, 128):
        file_full = file_all_factor * rank * ELEMENT_BYTES
        file_attention = file_attention_factor * rank * ELEMENT_BYTES
        lora_rows.append({
            'rank': rank,
            'full_decoder_file_GiB': file_full / GIB,
            'attention_only_file_GiB': file_attention / GIB,
            'default_buffer_GiB_per_GPU_per_slot': buffer_factor * rank * ELEMENT_BYTES / GIB,
            'default_buffer_GiB_all_GPUs_per_slot': buffer_factor * rank * ELEMENT_BYTES * TP / GIB,
            'full_adapters_under_3GiB_payload_only': (PACKAGE_LIMIT - 1) // file_full,
            'full_adapters_with_0_25GiB_resources': int((PACKAGE_LIMIT - 0.25 * GIB) // file_full),
            'attention_adapters_with_0_25GiB_resources': int((PACKAGE_LIMIT - 0.25 * GIB) // file_attention),
        })

    scenarios = []
    # Capacity values are SENSITIVITIES, not measured L4 totals. 22 is
    # deliberately conservative; NVIDIA's advertised 24 GB is not proof of
    # CUDA reporting 24 GiB. All keep vision enabled, matching the example.
    for capacity in (22, 22.5, 24):
        budget = 0.90 * capacity * GIB
        for reserve in (2, 4):
            for slots, rank in ((4, 32), (6, 32), (3, 64), (12, 16), (8, 32)):
                buffers = slots * buffer_factor * rank * ELEMENT_BYTES
                package = slots * file_all_factor * rank * ELEMENT_BYTES
                remaining_cache = budget - base_per_gpu - buffers - reserve * GIB
                for sessions in (1, 2, 4, 8):
                    decode = sessions * paged_kv(MAX_CONTEXT)
                    # Pessimistic independent peak per request: each gets an
                    # entire 2048-token chunk simultaneously. Their aggregate
                    # exceeds the scheduler budget when sessions > 1; this is
                    # an intentionally conservative envelope, not a trace.
                    independent_prefill = sessions * paged_kv(MAX_CONTEXT, 2048)
                    scenarios.append({
                        'hypothetical_CUDA_GiB_per_GPU': capacity,
                        'gpu_memory_utilization': 0.90,
                        'assumed_engine_overhead_GiB_per_GPU': reserve,
                        'adapter_slots': slots, 'max_rank': rank, 'sessions_32K': sessions,
                        'full_adapter_payload_GiB': package / GIB,
                        'package_payload_under_3GiB': package < PACKAGE_LIMIT,
                        'default_buffers_GiB_per_GPU': buffers / GIB,
                        'KV_envelope_GiB_per_GPU': remaining_cache / GIB,
                        'decode_working_total_GiB_per_GPU': (budget - remaining_cache + decode) / GIB,
                        'decode_headroom_GiB_per_GPU': (remaining_cache - decode) / GIB,
                        'conservative_independent_prefill_total_GiB_per_GPU': (budget - remaining_cache + independent_prefill) / GIB,
                        'conservative_prefill_headroom_GiB_per_GPU': (remaining_cache - independent_prefill) / GIB,
                        'decode_only_session_ceiling_not_throughput': max(0, math.floor(remaining_cache / paged_kv(MAX_CONTEXT))),
                    })

    result = {
        'date': '2026-10-06',
        'checkpoint_revision': '52f3f65bc7a02d555763bc923bd1d9094898219d',
        'organizer_wheelhouse_version': 28,
        'organizer_vllm_version': '0.19.1 with Gemma4 patches',
        'tensor_parallel_size': TP, 'max_model_len': MAX_CONTEXT,
        'architecture': dict(counts),
        'weights': {
            'checkpoint_payload_GiB': payload / GIB,
            'tied_lm_head_saving_GiB_total': head / GIB,
            'global_K_duplication_GiB_total': duplicate_k / GIB,
            'replicated_vision_and_connector_GiB_per_GPU': vision / GIB,
            'replicated_text_norms_GiB_per_GPU': replicated_text / GIB,
            'sharded_text_GiB_per_GPU': sharded_text / TP / GIB,
            'base_tensor_GiB_per_GPU_with_vision': base_per_gpu / GIB,
            'base_tensor_GiB_per_GPU_text_only_counterfactual': (base_per_gpu - vision) / GIB,
        },
        'adapter_factors': {'file_attention_params_per_rank': file_attention_factor,
                            'file_decoder_params_per_rank': file_all_factor,
                            'default_GPU_buffer_elements_per_rank_per_slot': buffer_factor},
        'assumptions': {
            'bf16_KV_and_lora': True,
            'hybrid_KV_manager_enabled_default': True,
            'default_L4_OPENAI_API_SERVER_batched_tokens': 2048,
            'default_max_num_seqs': 256,
            'illustrative_local_block_size': 16,
            'block_size_is_source_default_not_hardware_capture': True,
            'capacity_and_engine_reserve': 'Hypothetical CUDA totals and overhead, explicitly not GPU measurements.',
            'GPU_buffers': 'All decoder linear modules, partial TP sharding; empty global V slots also allocated; max rank shared by all slots.',
            'package_sizes': 'BF16 independent PEFT matrices, no embeddings, modules_to_save or training optimizer states; safetensors header/config add bytes.',
            'tensor_estimate_exclusions': 'Runtime repacking, extra graph/prefill/Punica workspaces, media buffers, fragmentation and memory held outside the profiled executor.',
            'scenarios': 'Working-use envelopes; vLLM normally reserves the residual KV pool, so nvidia-smi can be near 90% even with one request.',
            'upper_bound_warning': 'Cache capacity and file-size ceilings do not prove concurrency, throughput or quality.',
        },
        'cache_by_context': cache_rows, 'lora_by_rank': lora_rows,
        'scenarios': scenarios,
        'block_size_sensitivity_32K': [
            {'local_block': block, 'decode_GiB_per_GPU': paged_kv(MAX_CONTEXT, 1, block) / GIB,
             'prefill_chunk2048_GiB_per_GPU': paged_kv(MAX_CONTEXT, 2048, block) / GIB}
            for block in (16, 32, 64, 128)],
    }
    (ROOT / 'contest-results.json').write_text(json.dumps(result, indent=2) + '\n')
    for name, rows in (('cache-by-context', cache_rows), ('lora-by-rank', lora_rows), ('scenarios', scenarios)):
        with (ROOT / f'{name}.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps({k: result[k] for k in ('weights', 'cache_by_context', 'lora_by_rank')}, indent=2))


if __name__ == '__main__':
    main()
