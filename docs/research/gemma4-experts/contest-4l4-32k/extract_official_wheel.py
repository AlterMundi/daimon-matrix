#!/usr/bin/env python3
"""Extract selected Python sources from the public organizer wheel with ranges.

Never download weights or binary libraries; redirect URLs are kept in memory.
"""
import hashlib
import io
import json
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
URL = ('https://www.kaggle.com/api/v1/datasets/download/metric/'
       'gemma-4-developer-agent-wheelhouse/'
       'vllm-0.19.1-cp38-abi3-manylinux_2_31_x86_64.whl?datasetVersionNumber=28')
SIZE = 433132506


class RemoteFile(io.RawIOBase):
    def __init__(self):
        self.pos = 0
        self.cache = {}
        self.chunk = 1024 * 1024
        self.transferred = 0
        self.url = URL

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        self.pos = offset if whence == 0 else self.pos + offset if whence == 1 else SIZE + offset
        return self.pos

    def tell(self):
        return self.pos

    def read(self, size=-1):
        size = min(size if size >= 0 else SIZE - self.pos, SIZE - self.pos)
        if not size:
            return b''
        parts = []
        while size:
            index = self.pos // self.chunk
            if index not in self.cache:
                start, end = index * self.chunk, min((index + 1) * self.chunk, SIZE) - 1
                req = urllib.request.Request(self.url, headers={'Range': f'bytes={start}-{end}'})
                with urllib.request.urlopen(req, timeout=40) as r:
                    if r.status != 206 or r.headers.get('Content-Range') != f'bytes {start}-{end}/{SIZE}':
                        raise RuntimeError('Server did not honor the exact byte range')
                    self.url = r.geturl()
                    blob = r.read(end - start + 2)
                if len(blob) != end - start + 1:
                    raise RuntimeError('Wrong range length')
                self.cache[index] = blob
                self.transferred += len(blob)
            offset = self.pos % self.chunk
            n = min(size, len(self.cache[index]) - offset)
            parts.append(self.cache[index][offset:offset+n])
            self.pos += n
            size -= n
        return b''.join(parts)


members = [
    'vllm/model_executor/models/gemma4.py',
    'vllm/model_executor/models/gemma4_mm.py',
    'vllm/model_executor/models/utils.py',
    'vllm/model_executor/models/interfaces.py',
    'vllm/v1/core/kv_cache_utils.py',
    'vllm/v1/kv_cache_interface.py',
    'vllm/config/vllm.py',
    'vllm/config/lora.py',
    'vllm/lora/model_manager.py',
    'vllm/lora/layers/base_linear.py',
    'vllm/lora/layers/column_parallel_linear.py',
    'vllm/lora/layers/row_parallel_linear.py',
    'vllm/model_executor/layers/attention/attention.py',
    'vllm/v1/core/single_type_kv_cache_manager.py',
    'vllm/v1/worker/lora_model_runner_mixin.py',
    'vllm/model_executor/layers/quantization/compressed_tensors/schemes/compressed_tensors_wNa16.py',
    'vllm/lora/utils.py',
    'vllm/lora/layers/logits_processor.py',
    'vllm/config/scheduler.py',
    'vllm/config/cache.py',
    'vllm/engine/arg_utils.py',
]
remote = RemoteFile()
records = []
manifest_path = ROOT / 'official-vllm-source-manifest.json'
expected = {r['path']: r for r in json.loads(manifest_path.read_text())['members']} if manifest_path.exists() else {}
with zipfile.ZipFile(remote) as wheel:
    for name in members:
        if name not in wheel.namelist():
            print(json.dumps({'missing': name}), flush=True)
            continue
        path = ROOT / 'official-vllm-source' / name
        content = path.read_bytes() if path.exists() else wheel.read(name)
        if name in expected and hashlib.sha256(content).hexdigest() != expected[name]['sha256']:
            raise RuntimeError(f'Extracted member differs from archived evidence: {name}')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        records.append({'path': name, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
        print(json.dumps({'extracted': name, 'bytes': len(content)}), flush=True)
manifest = {'source': URL, 'wheelhouse_version': 28, 'wheel_bytes': SIZE,
            'http_range_bytes_transferred': remote.transferred, 'members': records}
output = ROOT / 'official-vllm-extraction-run.json' if expected else manifest_path
output.write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'files': len(records), 'range_bytes': remote.transferred}))
