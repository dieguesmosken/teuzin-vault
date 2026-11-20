# Software Bill of Materials (SBOM)

**Status:** initial inventory process; exact release SBOM not yet generated.

A complete SBOM must describe the exact software artifacts distributed, not only the dependency ranges in project manifests.

## Python environment

After installing the project and development dependencies in the release environment, capture installed packages and license metadata:

```powershell
python -m pip freeze
python -m pip install pip-licenses
pip-licenses --with-urls --with-description --format=markdown
```

Review the output manually. Package metadata can be incomplete or inaccurate; verify upstream license files for ambiguous or dual-licensed packages.

## Website

Commit `package-lock.json` and run:

```powershell
npm sbom --sbom-format=cyclonedx
```

Retain the generated CycloneDX document as a release artifact and review the licenses of all transitive packages.

## Native and bundled components

For Windows/Linux release artifacts, inspect:

- Qt libraries, plugins, and platform plugins actually bundled by the packager.
- Python runtime and standard-library build configuration.
- Zstandard shared/static library linkage.
- Operating-system libraries and WebAuthn components.
- Any icons, fonts, images, or other assets copied into the artifact.

## Release gate

Do not label an SBOM complete until it corresponds to a specific release artifact, includes transitive and native components, and has been reviewed. Store the reviewed SBOM with that release.
