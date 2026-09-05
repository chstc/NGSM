# Third-party notices

NGSM-authored source code is licensed under the BSD Zero Clause License
(0BSD); see [LICENSE](LICENSE).

The official GUI executable includes the Slint UI framework under
**GPL-3.0-only**. Distribution of the combined executable follows GPLv3;
the NGSM-authored files retain their permissive 0BSD license. Other
dependencies retain their respective licenses.

Each release includes:

- `GPL-3.0.txt`: the GPLv3 license text supplied with Slint.
- `DEPENDENCIES.txt`: the exact resolved Cargo package versions, declared
  license expressions, and upstream repositories. This list also includes
  build-time and platform-specific packages that may not be linked into
  the Windows executable.
- `ngsm-vVERSION-source.tar.gz`: the tagged project source, build scripts,
  lockfile, and vendored dependency sources with their original license
  files. Its `.cargo\config.toml` selects the bundled sources while retaining
  static C runtime linking.

To rebuild the source bundle, extract it on a Windows x64 machine with the
Rust MSVC toolchain and Windows SDK, then run:

```powershell
cargo build --frozen --release --target x86_64-pc-windows-msvc -p servicemanager-cli
```

Cargo does not need network access for this build. The Rust compiler,
standard library, MSVC build tools, and Windows SDK must already be
installed; these system/toolchain components are not included in the
source archive. `BUILD-INFO.json` records the release's toolchain and source
commit. The binary is unsigned; a checksum establishes file integrity, not
a publisher signature.
