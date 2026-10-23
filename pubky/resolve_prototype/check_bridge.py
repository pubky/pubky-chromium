#!/usr/bin/env python3
"""Build and exercise the pinned PKResolve CXX bridge in a temporary copy."""

import argparse
import pathlib
import shutil
import subprocess
import tempfile


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxxbridge", type=pathlib.Path, required=True)
    parser.add_argument("--compiler", default="c++")
    parser.add_argument("--allow-downloads", action="store_true")
    args = parser.parse_args()
    source = pathlib.Path(__file__).resolve().parents[2] / "third_party/pkarr"
    if not (source / "bindings/chromium/Cargo.toml").is_file():
        parser.error(
            "PKResolve is not initialized; run "
            "git submodule update --init -- third_party/pkarr"
        )
    generator = args.cxxbridge.resolve()
    version = run(str(generator), "--version", capture_output=True).stdout
    if version.strip() != "cxxbridge 1.0.194":
        parser.error("this prototype requires cxxbridge 1.0.194")
    smoke_test = pathlib.Path(__file__).with_name("bridge_smoke_test.cc")

    # Never create targets or lockfiles in the pinned dependency checkout.
    with tempfile.TemporaryDirectory(prefix="pubky-pkresolve-check-") as work:
        root = pathlib.Path(work)
        for name in ("Cargo.toml", "Cargo.lock", "pkresolve", "pkarr", "bindings", "relay"):
            original = source / name
            if original.is_dir():
                shutil.copytree(
                    original, root / name,
                    ignore=shutil.ignore_patterns("target", ".git"),
                )
            else:
                shutil.copy2(original, root / name)
        # Upstream ignores this standalone workspace's lockfile. Keep the
        # prototype's tested dependency graph independent of local Cargo state.
        shutil.copy2(
            pathlib.Path(__file__).with_name("bridge.Cargo.lock"),
            root / "bindings/chromium/Cargo.lock",
        )
        manifest = str(root / "bindings/chromium/Cargo.toml")
        cargo_options = ["--manifest-path", manifest, "--locked"]
        if not args.allow_downloads:
            cargo_options.append("--offline")
        run("cargo", "build", *cargo_options)
        bridge = str(root / "bindings/chromium/src/lib.rs")
        run(str(generator), bridge, "--header", "-o", str(root / "pkresolve.h"))
        run(str(generator), bridge, "-o", str(root / "pkresolve.cc"))
        (root / "rust").mkdir()
        run(str(generator), "--header", "-o", str(root / "rust/cxx.h"))
        executable = root / "bridge_smoke_test"
        run(
            args.compiler, "-std=c++17", "-fno-exceptions", "-I" + str(root),
            str(smoke_test), str(root / "pkresolve.cc"),
            str(root / "bindings/chromium/target/debug/libpkresolve_chromium.a"),
            "-ldl", "-pthread", "-lm", "-o", str(executable),
        )
        bundle = root / "bundle.json"
        fixture = run(
            "cargo", "run", "--quiet", *cargo_options,
            "--example", "make_bundle", "--", str(bundle), capture_output=True,
        )
        run(str(executable), fixture.stdout.strip(), str(bundle))


if __name__ == "__main__":
    main()
