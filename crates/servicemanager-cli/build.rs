// Compile the Windows resource script (icon and Cargo-derived version info).
//
// This keys off `CARGO_CFG_WINDOWS` — the *compilation target* — rather than
// `#[cfg(windows)]`, which only describes the build host. Using the target
// means a Windows cross-build still embeds the icon resource instead of
// silently producing an iconless executable, while a build that targets a
// non-Windows OS skips the step cleanly.
//
// Resource compiler: `embed_resource` invokes whichever resource compiler it
// discovers on the toolchain path — MSVC `rc.exe` or GNU `windres`. For
// reproducible *release* artifacts, build in a controlled environment with a
// pinned MSVC Build Tools / Windows SDK installation so `rc.exe` is a
// known-good compiler; do not depend on whatever happens to be on `PATH`.
// The build fails loudly (see the `.expect` below) when no compiler is
// found, so a release artifact can never be silently produced without the
// resource embedded.
fn main() {
    let target_is_windows = std::env::var_os("CARGO_CFG_WINDOWS").is_some();
    if target_is_windows {
        // Re-run when either the script or its referenced .ico changes.
        println!("cargo:rerun-if-changed=app.rc");
        println!("cargo:rerun-if-changed=assets/logo.ico");
        // On release builds, surface that the embedded resource was produced
        // by whichever resource compiler is on the toolchain path — a
        // reminder that release artifacts should come from a pinned,
        // controlled build environment (see the module comment above).
        let is_release = std::env::var("PROFILE")
            .map(|p| p == "release")
            .unwrap_or(false);
        if is_release {
            println!(
                "cargo:warning=release build: the Windows resource was compiled by the \
                 resource compiler discovered on PATH — confirm a pinned, trusted toolchain"
            );
        }
        let [major, minor, patch] = [
            env!("CARGO_PKG_VERSION_MAJOR"),
            env!("CARGO_PKG_VERSION_MINOR"),
            env!("CARGO_PKG_VERSION_PATCH"),
        ]
        .map(|component| {
            component
                .parse::<u16>()
                .expect("Windows version components must fit in an unsigned 16-bit integer")
        });
        let resource_defines = [
            format!("NGSM_FILE_VERSION={major},{minor},{patch},0"),
            format!("NGSM_VERSION_STRING=\"{}\\0\"", env!("CARGO_PKG_VERSION")),
        ];
        embed_resource::compile("app.rc", resource_defines)
            .manifest_optional()
            .expect(
                "failed to compile the Windows resource script `app.rc` \
                 (which embeds the icon `assets/logo.ico`). A Windows resource \
                 compiler must be available — `rc.exe` from the MSVC build \
                 tools, or `windres` from a GNU toolchain. Check that the \
                 build tools are installed and that `app.rc` and \
                 `assets/logo.ico` exist.",
            );
    }
}
