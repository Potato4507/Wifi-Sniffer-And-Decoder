# Changelog

## 3.0.0

This release reshapes the project around a narrow, explicit support matrix:

- `Ubuntu standalone`
- `Raspberry Pi OS standalone`
- `Windows 10/11 controller/analyzer + Ubuntu or Raspberry Pi OS remote capture`

Highlights:

- added product-profile awareness and command support gating
- made Windows a remote-first controller workflow instead of pretending full local Wi-Fi parity
- made Ubuntu and Raspberry Pi OS first-class standalone targets
- added Windows helper scripts for setup, validation, and daily remote capture
- added Linux helper scripts for setup, standalone validation, and daily local runs
- added remote bootstrap, doctor, service, integrity verification, and validation flows
- added packaging, release automation, and broader automated test coverage
- added a simulated validation matrix test pass for Ubuntu standalone, Raspberry Pi OS standalone, and Windows remote workflows

Still intentionally limited:

- native Windows monitor-mode capture remains experimental
- Linux distributions outside Ubuntu and Raspberry Pi OS remain best effort
- replay, payload decoding, and reconstruction remain heuristic

Release gate:

- the final supported-path release should only be treated as fully validated after real hardware smoke tests pass on:
  - Ubuntu standalone
  - Raspberry Pi OS standalone
  - Windows 10/11 + Ubuntu or Raspberry Pi OS remote capture
- `RELEASE_CHECKLIST.md` documents the exact release gate and what the simulated matrix does and does not prove
