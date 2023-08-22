use std::{
    path::{Path, PathBuf},
    process::Command,
};

const AARCH64: &str = "aarch64";

const RING_SRCS: &[(&[&str], &str)] = &[(&[AARCH64], SHA512_ARMV8)];

const SHA512_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha512-armv8.pl";

fn c_flags() -> &'static [&'static str] {
    &[
        "-std=c1x", // GCC 4.6 requires "c1x" instead of "c11"
        "-Wbad-function-cast",
        "-Wnested-externs",
        "-Wstrict-prototypes",
    ]
}

fn cpp_flags() -> &'static [&'static str] {
    &[
        "-pedantic",
        "-pedantic-errors",
        "-Wall",
        "-Wextra",
        "-Wcast-align",
        "-Wcast-qual",
        "-Wconversion",
        "-Wenum-compare",
        "-Wfloat-equal",
        "-Wformat=2",
        "-Winline",
        "-Winvalid-pch",
        "-Wmissing-field-initializers",
        "-Wmissing-include-dirs",
        "-Wredundant-decls",
        "-Wshadow",
        "-Wsign-compare",
        "-Wsign-conversion",
        "-Wundef",
        "-Wuninitialized",
        "-Wwrite-strings",
        "-fno-strict-aliasing",
        "-fvisibility=hidden",
    ]
}

const LD_FLAGS: &[&str] = &[];

// None means "any OS" or "any target". The first match in sequence order is
// taken.
const ASM_TARGETS: &[(&str, Option<&str>, Option<&str>)] = &[
    ("aarch64", Some("ios"), Some("ios64")),
    ("aarch64", Some("macos"), Some("ios64")),
    ("aarch64", None, Some("linux64")),
    ("arm", Some("ios"), Some("ios32")),
    ("arm", None, Some("linux32")),
    ("wasm32", None, None),
];

fn main() {
    ring_build_rs_main();
}

fn ring_build_rs_main() {
    use std::env;

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let (obj_ext, obj_opt) = ("o", "-o");

    // Published builds are always release builds.
    let is_debug = env::var("DEBUG").unwrap() != "false";

    let target = Target {
        arch,
        os,
        env,
        obj_ext,
        obj_opt,
        is_debug,
    };

    build_c_code(&target, &out_dir);
    //check_all_files_tracked()
}

struct Target {
    arch: String,
    os: String,
    env: String,
    obj_ext: &'static str,
    obj_opt: &'static str,
    is_debug: bool,
}

fn build_c_code(target: &Target, out_dir: &Path) {
    fn is_none_or_equals<T>(opt: Option<T>, other: T) -> bool
    where
        T: PartialEq,
    {
        if let Some(value) = opt {
            value == other
        } else {
            true
        }
    }

    let (_, _, perlasm_format) = ASM_TARGETS
        .iter()
        .find(|entry| {
            let &(entry_arch, entry_os, _) = *entry;
            entry_arch == target.arch && is_none_or_equals(entry_os, &target.os)
        })
        .unwrap();

    let warnings_are_errors = true;

    let asm_srcs = if let Some(perlasm_format) = perlasm_format {
        let perlasm_src_dsts = vec![(PathBuf::from("crypto/fipsmodule/sha/asm/sha512-armv8.pl"), PathBuf::from("/root/ring/target/aarch64-unknown-linux-gnu/release/build/ring-2d78022b4dc8d8f4/out/sha256-armv8-linux64.S"))];
        perlasm(
            &perlasm_src_dsts[..],
            &target.arch,
            perlasm_format,
        );

        asm_srcs(perlasm_src_dsts)
    } else {
        Vec::new()
    };

    let core_srcs = sources_for_arch(&target.arch)
        .into_iter()
        .filter(|p| !is_perlasm(&p))
        .collect::<Vec<_>>();

    let libs = [
        ("ring-core", &core_srcs[..], &asm_srcs[..]),
    ];

    // XXX: Ideally, ring-test would only be built for `cargo test`, but Cargo
    // can't do that yet.
    libs.iter().for_each(|&(lib_name, srcs, additional_srcs)| {
        build_library(
            &target,
            &out_dir,
            lib_name,
            srcs,
            additional_srcs,
            warnings_are_errors,
        )
    });

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.to_str().expect("Invalid path")
    );
}

fn build_library(
    target: &Target,
    out_dir: &Path,
    lib_name: &str,
    srcs: &[PathBuf],
    additional_srcs: &[PathBuf],
    warnings_are_errors: bool,
) {
    // Compile all the (dirty) source files into object files.
    let objs = additional_srcs
        .iter()
        .chain(srcs.iter())
        .filter(|f| &target.env != "msvc" || f.extension().unwrap().to_str().unwrap() != "S")
        .map(|f| compile(f, target, warnings_are_errors, out_dir))
        .collect::<Vec<_>>();

    // Rebuild the library if necessary.
    let lib_path = PathBuf::from(out_dir).join(format!("lib{}.a", lib_name));

    let mut c = cc::Build::new();

    for f in LD_FLAGS {
        let _ = c.flag(&f);
    }
    match target.os.as_str() {
        "macos" => {
            let _ = c.flag("-fPIC");
            let _ = c.flag("-Wl,-dead_strip");
        }
        _ => {
            let _ = c.flag("-Wl,--gc-sections");
        }
    }
    for o in objs {
        let _ = c.object(o);
    }

    // Handled below.
    let _ = c.cargo_metadata(false);

    c.compile(
        lib_path
            .file_name()
            .and_then(|f| f.to_str())
            .expect("No filename"),
    );

    // Link the library. This works even when the library doesn't need to be
    // rebuilt.
    println!("cargo:rustc-link-lib=static={}", lib_name);
}

fn compile(
    p: &Path,
    target: &Target,
    warnings_are_errors: bool,
    out_dir: &Path,
) -> String {
    let ext = p.extension().unwrap().to_str().unwrap();
    if ext == "obj" {
        p.to_str().expect("Invalid path").into()
    } else {
        let mut out_path = out_dir.join(p.file_name().unwrap());
        assert!(out_path.set_extension(target.obj_ext));
        let cmd = cc(p, ext, target, warnings_are_errors, &out_path);
        run_command(cmd);
        out_path.to_str().expect("Invalid path").into()
    }
}

fn cc(
    file: &Path,
    ext: &str,
    target: &Target,
    warnings_are_errors: bool,
    out_dir: &Path,
) -> Command {
    let is_musl = target.env.starts_with("musl");

    let mut c = cc::Build::new();
    let _ = c.include("include");
    match ext {
        "c" => {
            for f in c_flags() {
                let _ = c.flag(f);
            }
        }
        "S" => (),
        e => panic!("Unsupported file extension: {:?}", e),
    };
    for f in cpp_flags() {
        let _ = c.flag(&f);
    }
    if target.os != "none" && target.os != "redox" && target.arch != "wasm32" {
        let _ = c.flag("-fstack-protector");
    }

    match (target.os.as_str(), target.env.as_str()) {
        // ``-gfull`` is required for Darwin's |-dead_strip|.
        ("macos", _) => {
            let _ = c.flag("-gfull");
        }
        (_, "msvc") => (),
        _ => {
            let _ = c.flag("-g3");
        }
    };
    if !target.is_debug {
        let _ = c.define("NDEBUG", None);
    }

    if &target.env == "msvc" {
        if std::env::var("OPT_LEVEL").unwrap() == "0" {
            let _ = c.flag("/Od"); // Disable optimization for debug builds.
                                   // run-time checking: (s)tack frame, (u)ninitialized variables
            let _ = c.flag("/RTCsu");
        } else {
            let _ = c.flag("/Ox"); // Enable full optimization.
        }
    }

    // Allow cross-compiling without a target sysroot for these targets.
    //
    // poly1305_vec.c requires <emmintrin.h> which requires <stdlib.h>.
    if (target.arch == "wasm32" && target.os == "unknown")
        || (target.os == "linux" && is_musl && target.arch != "x86_64")
    {
        if let Ok(compiler) = c.try_get_compiler() {
            // TODO: Expand this to non-clang compilers in 0.17.0 if practical.
            if compiler.is_like_clang() {
                let _ = c.flag("-nostdlibinc");
                let _ = c.define("GFp_NOSTDLIBINC", "1");
            }
        }
    }

    if warnings_are_errors {
        let flag = if &target.env != "msvc" {
            "-Werror"
        } else {
            "/WX"
        };
        let _ = c.flag(flag);
    }
    if is_musl {
        // Some platforms enable _FORTIFY_SOURCE by default, but musl
        // libc doesn't support it yet. See
        // http://wiki.musl-libc.org/wiki/Future_Ideas#Fortify
        // http://www.openwall.com/lists/musl/2015/02/04/3
        // http://www.openwall.com/lists/musl/2015/06/17/1
        let _ = c.flag("-U_FORTIFY_SOURCE");
    }

    let mut c = c.get_compiler().to_command();
    let _ = c
        .arg("-c")
        .arg(format!(
            "{}{}",
            target.obj_opt,
            out_dir.to_str().expect("Invalid path")
        ))
        .arg(file);
    c
}

fn run_command_with_args<S>(command_name: S, args: &[String])
where
    S: AsRef<std::ffi::OsStr> + Copy,
{
    let mut cmd = Command::new(command_name);
    let _ = cmd.args(args);
    run_command(cmd)
}

fn run_command(mut cmd: Command) {
    eprintln!("running {:?}", cmd);
    let status = cmd.status().unwrap_or_else(|e| {
        panic!("failed to execute [{:?}]: {}", cmd, e);
    });
    if !status.success() {
        panic!("execution failed");
    }
}

fn sources_for_arch(arch: &str) -> Vec<PathBuf> {
    RING_SRCS
        .iter()
        .filter(|&&(archs, _)| archs.is_empty() || archs.contains(&arch))
        .map(|&(_, p)| PathBuf::from(p))
        .collect::<Vec<_>>()
}

fn asm_srcs(perlasm_src_dsts: Vec<(PathBuf, PathBuf)>) -> Vec<PathBuf> {
    perlasm_src_dsts
        .into_iter()
        .map(|(_src, dst)| dst)
        .collect::<Vec<_>>()
}

fn is_perlasm(path: &PathBuf) -> bool {
    path.extension().unwrap().to_str().unwrap() == "pl"
}

fn perlasm(
    src_dst: &[(PathBuf, PathBuf)],
    arch: &str,
    perlasm_format: &str,
) {
    for (src, dst) in src_dst {
        let mut args = Vec::<String>::new();
        args.push(src.to_string_lossy().into_owned());
        args.push(perlasm_format.to_owned());
        if arch == "x86" {
            args.push("-fPIC".into());
            args.push("-DOPENSSL_IA32_SSE2".into());
        }
        // Work around PerlAsm issue for ARM and AAarch64 targets by replacing
        // back slashes with forward slashes.
        let dst = dst
            .to_str()
            .expect("Could not convert path")
            .replace("\\", "/");
        args.push(dst);
        run_command_with_args(&get_command("PERL_EXECUTABLE", "perl"), &args);
    }
}

fn get_command(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.into())
}
