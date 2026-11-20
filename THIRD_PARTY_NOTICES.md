# Third-party notices

**Status: preliminary inventory — 2026-11-20.**

The Apache-2.0 license in the repository applies to original Teuzin Vault work only. It does not relicense dependencies, bundled runtimes, system libraries, or generated assets.

## Python application dependencies

| Component                  | Declared requirement | License information to preserve                                                                                           | Notes                                                                   |
| -------------------------- | -------------------: | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| PySide6 / Qt for Python    |             `>=6.12` | Qt for Python components are offered under LGPLv3/GPLv3 or commercial terms, depending on the component and distribution. | Confirm the exact Qt modules and redistribution model before packaging. |
| cryptography               |               `>=45` | Apache-2.0 OR BSD-3-Clause                                                                                                | Preserve applicable upstream notices.                                   |
| python-fido2               |            `>=2.2.1` | Primarily BSD-2-Clause; upstream also identifies components under Apache-2.0 and MPL-2.0.                                 | Inspect the exact installed release and included files.                 |
| pytest (development)       |                `>=8` | MIT                                                                                                                       | Development-only dependency.                                            |
| pytest-cov (development)   |                `>=6` | MIT                                                                                                                       | Development-only dependency; includes additional dependencies.          |
| setuptools (build backend) |               `>=75` | MIT                                                                                                                       | Build-time dependency.                                                  |

## Runtime and platform components

- Python standard library modules are supplied by the selected Python runtime and are not separately installed from this project's Python dependency list.
- `compression.zstd` is provided by Python 3.14+; verify the linked/bundled Zstandard implementation and its license in each packaged runtime.
- Windows WebAuthn, FIDO2 authenticators, and platform cryptographic services are external platform components. This project does not redistribute their firmware or operating-system binaries.

## Website toolchain

The following versions and license declarations were inspected in the Windows development environment for this site.

| Component             | Version | Declared license                 | Role / notes                                                                                                                                                                                                                                                                                                                |
| --------------------- | ------: | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Astro                 |  7.4.12 | MIT                              | Static site generator.                                                                                                                                                                                                                                                                                                      |
| Starlight             |  0.43.1 | MIT                              | Documentation integration for Astro.                                                                                                                                                                                                                                                                                        |
| Prettier              |  3.10.1 | MIT                              | Development-only formatting tool.                                                                                                                                                                                                                                                                                           |
| prettier-plugin-astro |   1.1.2 | MIT                              | Development-only formatter plugin.                                                                                                                                                                                                                                                                                          |
| lightningcss          |  1.33.0 | MPL-2.0                          | CSS tooling in the website build dependency tree. Preserve the MPL-2.0 notice.                                                                                                                                                                                                                                              |
| sharp                 |  0.35.5 | Apache-2.0                       | Image processing dependency in the build toolchain.                                                                                                                                                                                                                                                                         |
| @img/sharp-win32-x64  |  0.35.5 | Apache-2.0 AND LGPL-3.0-or-later | Windows-specific package present in the inspected environment. Its package metadata declares both licenses, while the inspected package-level `LICENSE` file contains Apache-2.0 text. The LGPL-covered component and corresponding license/source obligations require further upstream verification before redistribution. |

The npm lockfile and generated CycloneDX SBOM describe the dependency tree, including optional and platform-specific packages that may not be installed on the current machine. The SBOM inspected for this inventory contained 368 components. It is not a list of 368 components necessarily shipped to website visitors.

The current Windows installation was checked separately from the lockfile. In particular, the inspected `@img/sharp-libvips-win32-x64` package was not installed. Other platform-specific `sharp` and `lightningcss` variants appearing in the SBOM must not be described as installed or distributed solely because they appear in the dependency inventory.

Prettier and its Astro plugin are development tools. The presence of a package in the build dependency tree does not, by itself, establish that it is included in the published static website.

## GitHub Actions

The Pages workflow uses third-party GitHub Actions. Their source repositories and license files must be checked at the exact pinned revisions before redistribution or reuse. Workflow references are pinned to commit SHAs to make the selected source revisions explicit.

## Required release checks

1. Generate a Python dependency inventory from the exact release environment.
2. Generate an npm SBOM from the committed lockfile.
3. Inspect transitive licenses, optional platform packages, bundled Qt plugins, platform libraries, and Zstandard linkage.
4. Investigate the LGPL-3.0-or-later declaration associated with `@img/sharp-win32-x64` and identify the covered component and applicable distribution obligations.
5. Include required license texts and upstream notices in every distributed package.
6. Re-run the inventory whenever dependencies or build artifacts change.
7. Distinguish development/build dependencies from components actually included in each release artifact.

This file is an attribution register, not legal advice and not a substitute for reviewing the license terms of the exact artifacts shipped.
