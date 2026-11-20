# Third-party notices

**Status: preliminary inventory — 2026-11-20.**

The Apache-2.0 license in the repository applies to original Teuzin Vault work only. It does not relicense dependencies, bundled runtimes, system libraries, or generated assets.

## Python application dependencies

| Component | Declared requirement | License information to preserve | Notes |
|---|---:|---|---|
| PySide6 / Qt for Python | `>=6.12` | Qt for Python components are offered under LGPLv3/GPLv3 or commercial terms, depending on the component and distribution. | Confirm the exact Qt modules and redistribution model before packaging. |
| cryptography | `>=45` | Apache-2.0 OR BSD-3-Clause | Preserve applicable upstream notices. |
| python-fido2 | `>=2.2.1` | Primarily BSD-2-Clause; upstream also identifies components under Apache-2.0 and MPL-2.0. | Inspect the exact installed release and included files. |
| pytest (development) | `>=8` | MIT | Development-only dependency. |
| pytest-cov (development) | `>=6` | MIT | Development-only dependency; includes additional dependencies. |
| setuptools (build backend) | `>=75` | MIT | Build-time dependency. |

## Runtime and platform components

- Python standard library modules are supplied by the selected Python runtime and are not separately installed from this project's Python dependency list.
- `compression.zstd` is provided by Python 3.14+; verify the linked/bundled Zstandard implementation and its license in each packaged runtime.
- Windows WebAuthn, FIDO2 authenticators, and platform cryptographic services are external platform components. This project does not redistribute their firmware or operating-system binaries.

## Website toolchain

| Component | Version selected for this site | License |
|---|---:|---|
| Astro | 7.4.12 | MIT |
| Starlight | 0.43.1 | MIT |

The JavaScript dependency tree is transitive and must be captured from the generated `package-lock.json` / npm SBOM before a release. Do not treat this table as a complete binary-distribution SBOM.

## GitHub Actions

The Pages workflow uses third-party GitHub Actions. Their source repositories and license files must be checked at the exact pinned revisions before redistribution or reuse. Workflow references are pinned to commit SHAs to make the selected source revisions explicit.

## Required release checks

1. Generate a Python dependency inventory from the exact release environment.
2. Generate an npm SBOM from the committed lockfile.
3. Inspect transitive licenses, bundled Qt plugins, platform libraries, and Zstandard linkage.
4. Include required license texts and upstream notices in every distributed package.
5. Re-run the inventory whenever dependencies or build artifacts change.

This file is an attribution register, not legal advice and not a substitute for reviewing the license terms of the exact artifacts shipped.
