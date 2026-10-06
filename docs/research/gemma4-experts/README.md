# Gemma 4 competition research

Start with [HANDOFF.md](HANDOFF.md). It links the current analysis, historical
background, reproducible calculations and the next empirical experiment.

The archive uses public model metadata and stdlib calculators. It contains no
model weights, adapters, binary wheels, private memory or machine-specific
configuration. It can be cloned and continued on another host.

```bash
python3 docs/research/gemma4-experts/contest-4l4-32k/calculate_contest.py
python3 docs/research/gemma4-experts/2026-10-06/calculate_memory.py
python3 docs/research/gemma4-experts/verify_publication.py
```

The first command reproduces competition-specific results; the second reproduces
the archived consumer-GPU antecedents. The verifier checks public artifact hashes,
local Markdown links and both calculators in a temporary copy, without network
or GPU access. Temporary verification directories are removed automatically.

To inspect the organizer's pinned vLLM Python source with network access, run
`contest-4l4-32k/extract_official_wheel.py`. It extracts selected ZIP members by
HTTP Range without downloading model weights or binary libraries. Source recovery
checks recovered members against the committed hashes and writes its run record
separately. Generated source/run files are ignored by Git; the publication
manifest stays unchanged.

This research does not enroll a team, accept competition terms, submit an entry,
train adapters or deploy a Matrix runtime. Those actions have not occurred here.
