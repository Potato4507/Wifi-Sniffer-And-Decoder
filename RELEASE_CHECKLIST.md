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

## Step 12: enforced release gate

The release workflow now expects real validation artifacts in `validation_matrix/` and runs:

```bash
python scripts/release_gate.py \
  --ubuntu-report validation_matrix/ubuntu_standalone_validation.json \
  --pi-report validation_matrix/pi_standalone_validation.json \
  --windows-report validation_matrix/windows_remote_validation.json \
  --sample-report validation_matrix/sample_text_analysis.json \
  --sample-report validation_matrix/sample_video_analysis.json
```

That command checks:

- Ubuntu standalone validation report
- Raspberry Pi OS standalone validation report
- Windows remote validation report
- qualified adapter evidence from the Linux validation reports
- at least one supported decode/replay sample analysis report

The tag-based release workflow should now be treated as blocked until that gate passes.

Recommended closeout order:

1. write the Ubuntu standalone validation report into `validation_matrix/ubuntu_standalone_validation.json`
2. write the Raspberry Pi OS validation report into `validation_matrix/pi_standalone_validation.json`
3. write the Windows remote validation report into `validation_matrix/windows_remote_validation.json`
4. copy one or more supported sample `analysis_report.json` files into `validation_matrix/`
5. run `python scripts/release_gate.py ...`
6. only tag the release after that command returns success
