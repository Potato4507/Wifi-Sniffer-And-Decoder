# Release Checklist

This file is the release gate for the narrowed support matrix.

## Supported product modes

- `Ubuntu standalone`
- `Raspberry Pi OS standalone`
- `Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture`

## Step 6: validation

### Simulated validation matrix

These checks are automated and should pass before any release candidate is treated as ready:

```bash
python -m pytest -q tests/test_validation_matrix.py
python -m pytest -q
python -m compileall -q wifi_pipeline
```

What this proves:

- product-profile routing is correct
- `validate-local` and `validate-remote` generate the expected reports
- Ubuntu standalone, Raspberry Pi OS standalone, and Windows remote flows are wired correctly under mocked conditions

What this does not prove:

- real adapter behavior
- monitor-mode support
- remote privilege edge cases on real Linux devices
- SSH/network conditions
- real packet quality and capture reliability

### Real hardware validation gate

These runs are still required before the support matrix should be treated as fully validated:

```bash
./validate_local.sh --interface wlan0
```

Run that once on:

- Ubuntu
- Raspberry Pi OS

And run this on Windows with a Linux capture device:

```powershell
.\validate_remote.ps1 -Host pi@raspberrypi -Interface wlan0
```

Expected reports:

- `pipeline_output/standalone_validation_report.json`
- `pipeline_output/validation_report.json`

Expected pass conditions:

- `environment_ok: true`
- interface check passes
- smoke capture succeeds
- processing smoke succeeds
- `overall_ok: true`

## Step 7: release prep

These software-side items should be complete:

- README reflects the narrowed support matrix
- changelog reflects the release story
- packaging includes helper scripts and release docs
- CI, tests, and build checks are green

## Release decision

Treat the release as:

- `software-ready` when the simulated validation matrix passes and packaging is green
- `fully validated` only after the real hardware validation gate above passes
