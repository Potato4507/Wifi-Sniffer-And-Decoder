# Ecosystem Map

This repo is a Wi-Fi capture and passive analysis pipeline, not a general-purpose recon, cracking, or exploitation framework.

Your list is still useful, but only if we separate:

- ideas worth borrowing into the core pipeline,
- tools that should stay external and feed us results through adapters,
- tooling that does not belong in-tree for scope, safety, or licensing reasons.

## Ground Rules

- Borrow concepts and data shapes first. Do not blindly copy source code.
- Verify license obligations before reusing any implementation. This list spans mixed permissive and copyleft licenses.
- Prefer adapter boundaries over vendoring large upstream projects.
- Keep the core pipeline passive: capture -> extract -> detect -> analyze -> enrich -> report.
- Keep offensive, internet-scale, brute-force, or credential-focused tooling out of the main runtime.

## High-Fit For Core Integration

These are the best matches for the current codebase because they support passive packet interpretation, extracted-artifact triage, or reporting.

| Bucket | Repos from your list | Best use here |
|---|---|---|
| Passive protocol inspiration | `suricata`, `bro-pkg`/Zeek, `packetbeat` | Borrow signature/enrichment ideas for `wifi_pipeline/extract.py` and `wifi_pipeline/analysis.py` without embedding a full IDS |
| Extracted file triage | `ExifTool`, `exif-py`, `hachoir`, `binwalk`, `bulk_extractor`, `foremost`, `scalpel`, `oletools`, `pdf-parser`, `peepdf`, `pefile`, `yara`, `yara-python`, `capa`, `stringsifter`, `flare-floss` | Run as optional post-extraction enrichers on units or reconstructed artifacts |
| Reporting and evidence browsing | `sqlite-utils`, `datasette`, `jq`, `gron` | Convert pipeline JSON into searchable local evidence stores and better dashboard drill-down |
| Case/timeline export | `timesketch`, `plaso`, `chainsaw`, `velociraptor`, `GRR` | Export artifacts and timestamps out of this repo instead of reimplementing those platforms |

## Adapter-Only Candidates

These can be useful as companion tools, but they should stay outside the core Wi-Fi pipeline. If we touch them at all, the right shape is "import their JSON/CLI output" rather than "merge their code into this package."

| Bucket | Repos from your list | Why adapter-only |
|---|---|---|
| Asset and DNS discovery | `amass`, `subfinder`, `assetfinder`, `dnsx`, `massdns`, `findomain`, `dnsrecon`, `fierce`, `Sublist3r`, `knock`, `uncover`, `dnsgen`, `puredns`, `dnstwist`, `passivedns` | Useful for broader investigations, but not part of packet capture or pcap decoding |
| Web enumeration and URL mining | `Photon`, `ParamSpider`, `LinkFinder`, `JSParser`, `waybackurls`, `gau`, `hakrawler`, `katana`, `subjs`, `unfurl`, `qsreplace` | Good sidecar reconnaissance, but should not reshape this repo's primary workflow |
| OSINT and identity collection | `theHarvester`, `Sherlock`, `Maigret`, `SpiderFoot`, `recon-ng`, `Maltego-Transforms`, `metagoofil`, `goofile` | Case-building companions, not capture-pipeline stages |
| Visual validation | `EyeWitness`, `aquatone`, `WitnessMe` | Better as downstream evidence snapshots after another tool finds targets |
| CTI/case management | `MISP`, `OpenCTI`, `Cortex`, `TheHive`, `securityonion` | Strong external destinations or peers, not something to absorb into a Wi-Fi analyzer |
| Secret scanning | `GitDorker`, `trufflehog`, `gitleaks`, `DumpsterDiver` | Better as CI or repository-audit tooling than runtime logic in this project |

## Keep Out Of Tree

These do not fit the repo's scope and should not be pulled into the codebase.

| Bucket | Repos from your list | Why keep out |
|---|---|---|
| Password cracking and brute force | `hashcat`, `john`, `hydra`, `patator`, `medusa`, `crowbar`, `CeWL`, `crunch`, `SecLists`, `hashcat-utils`, `maskprocessor`, `statsprocessor`, `princeprocessor`, `PACK`, `mentalist`, `rsmangler`, `wordlists`, `hash-identifier` | They turn the project into a credential-attack tool instead of a passive analyzer |
| Active scanning and network attack | `masscan`, `mitm6` | Not aligned with the current passive pipeline and adds obvious misuse risk |
| Reverse engineering workbenches | `radare2`, `ghidra`, `pwndbg`, `gef`, `ropper`, `angr`, `pwntools`, `rekall`, `volatility3`, `sleuthkit`, `autopsy` | Great analyst workstation tools, but far too large and orthogonal to embed here |

## Best Extension Points In This Repo

The current code already has good insertion points for safe, high-signal features:

- `wifi_pipeline/extract.py`
  Add optional artifact-enrichment hooks after units are written.
- `wifi_pipeline/analysis.py`
  Merge passive signature hits, file metadata, and post-extraction triage into stream scoring.
- `wifi_pipeline/corpus.py`
  Archive enrichment metadata alongside stream fingerprints for later similarity matches.
- `wifi_pipeline/webapp.py`
  Surface enrichment summaries, evidence links, and export actions in the dashboard.

## Recommended Build Order

If we start pulling from this ecosystem, the safest and most coherent order is:

1. Add an `enrich` stage for extracted units and reconstructed files.
2. Store enrichment output as JSON in `pipeline_output`.
3. Add a SQLite export so results are queryable in Datasette.
4. Add adapter modules for external passive tools that import their existing results.
5. Leave scanning, brute force, cracking, and attack automation outside the repo.

## Concrete Shortlist

If the goal is "what should we actually borrow from first," the shortlist is:

- `suricata` and Zeek ideas for protocol- and metadata-enrichment patterns
- `ExifTool`, `hachoir`, `binwalk`, `bulk_extractor`, `yara`, `pefile`, `oletools`, and `capa` as optional offline enrichers
- `sqlite-utils` and `datasette` for evidence indexing and browsing
- `jq` and `gron` style output ergonomics for easier report inspection

Everything else is either a sidecar investigation tool or a different product entirely.
