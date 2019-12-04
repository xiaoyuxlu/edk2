# Rust for EDKII

**This project is an experiment and should not be used production workloads.**

# Build Status

<table>
  <tr>
    <th>Host Type</th>
    <th>Toolchain</th>
    <th>Branch</th>
    <th>Build Status</th>
    <th>Test Status</th>
    <th>Code Coverage</th>
  </tr>
  <tr>
    <td>Windows</td>
    <td>VS2019</td>
    <td>master</td>
    <td>
      <a  href="https://dev.azure.com/tianocore/edk2-ci/_build/latest?definitionId=32&branchName=master">
      <img src="https://dev.azure.com/tianocore/edk2-ci/_apis/build/status/Windows%20VS2019%20CI?branchName=master"/></a>
    </td>
    <td>
      <a  href="https://dev.azure.com/tianocore/edk2-ci/_build/latest?definitionId=32&branchName=master">
      <img src="https://img.shields.io/azure-devops/tests/tianocore/edk2-ci/32.svg"/></a>
    </td>
    <td>
      <a  href="https://dev.azure.com/tianocore/edk2-ci/_build/latest?definitionId=32&branchName=master">
      <img src="https://img.shields.io/badge/coverage-coming_soon-blue"/></a>
    </td>
  </tr>
  <tr>
    <td>Ubuntu</td>
    <td>GCC</td>
    <td>master</td>
    <td>
      <a  href="https://dev.azure.com/tianocore/edk2-ci/_build/latest?definitionId=31&branchName=master">
      <img src="https://dev.azure.com/tianocore/edk2-ci/_apis/build/status/Ubuntu%20GCC5%20CI?branchName=master"/></a>
    </td>
    <td>
      <a  href="https://dev.azure.com/tianocore/edk2-ci/_build/latest?definitionId=31&branchName=master">
      <img src="https://img.shields.io/azure-devops/tests/tianocore/edk2-ci/31.svg"/></a>
    </td>
    <td>
      <a  href="https://dev.azure.com/tianocore/edk2-ci/_build/latest?definitionId=31&branchName=master">
      <img src="https://img.shields.io/badge/coverage-coming_soon-blue"/></a>
    </td>
  </tr>
</table>

[More CI Build information](.pytool/Readme.md)

# License Details

The majority of the content in the EDK II open source project uses a
[BSD-2-Clause Plus Patent License](License.txt).  The EDK II open source project
contains the following components that are covered by additional licenses:
* [BaseTools/Source/C/BrotliCompress](BaseTools/Source/C/BrotliCompress/LICENSE)
* [MdeModulePkg/Library/BrotliCustomDecompressLib](MdeModulePkg/Library/BrotliCustomDecompressLib/LICENSE)
* [BaseTools/Source/C/LzmaCompress](BaseTools/Source/C/LzmaCompress/LZMA-SDK-README.txt)
* [MdeModulePkg/Library/LzmaCustomDecompressLib](MdeModulePkg/Library/LzmaCustomDecompressLib/LZMA-SDK-README.txt)
* [IntelFrameworkModulePkg/Library/LzmaCustomDecompressLib/Sdk](IntelFrameworkModulePkg/Library/LzmaCustomDecompressLib/LZMA-SDK-README.txt)
* [BaseTools/Source/C/VfrCompile/Pccts](BaseTools/Source/C/VfrCompile/Pccts/RIGHTS)
* [MdeModulePkg/Universal/RegularExpressionDxe/Oniguruma](MdeModulePkg/Universal/RegularExpressionDxe/Oniguruma/README)
* [OvmfPkg](OvmfPkg/License.txt)
* [CryptoPkg/Library/OpensslLib/openssl](https://github.com/openssl/openssl/blob/50eaac9f3337667259de725451f201e784599687/LICENSE)
* [ArmPkg/Library/ArmSoftFloatLib/berkeley-softfloat-3](https://github.com/ucb-bar/berkeley-softfloat-3/blob/b64af41c3276f97f0e181920400ee056b9c88037/COPYING.txt)

1) Install rust

1.1) download the source code

We need add patch for i686-unknown-uefi target. (https://github.com/jyao1/rust)

1.2) follow readme.md to generate config.toml.

NOTE:

* set lld = true to build rust-lld.
* set extended = true to build rust-lld.
* set docs = false to save build time.

Linux OS:

* set prefix, sysconfdir = <local dir> in Linux OS.

Windows OS:

* set python = "python" in Windows OS.
* set buid, host, target = x86_64-pc-windows-msvc in Windows OS.
* set allow-old-toolchain = true , if visual studio < vs2019

1.3) follow readme.md to build the source.

```
./x.py build
```

1.4) Install rust and cargo.

1.4.1) For Linux OS:

Use below commend to install.

```
./x.py install
./x.py install cargo
```

* rustc is at <prefix>/bin.
* rust-lld is at <prefix>/lib/rustlib/x86_64-unknown-linux-gnu/bin.

```
export RUST_PREFIX=<rust install dir>
export PATH=$RUST_PREFIX/bin:$RUST_PREFIX/lib/rustlib/x86_64-unknown-linux-gnu/bin:$PATH
export RUST_SRC=<rust> # modify to the rust git.
export XARGO_RUST_SRC=$RUST_SRC/src
```

1.4.2) For Windows OS:

Set CARGO_HOME environment (default to ~/.cargo.  windows example: c:\users\<user>\.cargo)

Add binary location to PATH (Assume RUST_SRC=<rust> @REM modify to the rust git.)

* rustc.exe toolchain is at %RUST_SRC%\build\x86_64-pc-windows-msvc\stage2\bin
* cargo.exe and tools is at %RUST_SRC%\build\x86_64-pc-windows-msvc\stage2-tools-bin

```
set RUST_SRC=<rust> @REM modify to the rust git.
set CARGO_HOME=c:\work\.cargo
set PATH=%CARGO_HOME%\bin;%RUST_SRC%\build\x86_64-pc-windows-msvc\stage2\bin;%RUST_SRC%\build\x86_64-pc-windows-msvc\stage2-tools-bin;%PATH%
set XARGO_RUST_SRC=%RUST_SRC%\src
```

Other way:
Copy cargo.exe from %RUST_SRC%\build\x86_64-pc-windows-msvc\stage2-tools-bin to %RUST_SRC%\build\x86_64-pc-windows-msvc\stage2\bin

```
set RUST_SRC=<rust> @REM modify to the rust git.
rustup toolchain link rust-uefi %RUST_SRC%x\build\x86_64-pc-windows-msvc\stage2
rustup default rust-uefi
set XARGO_RUST_SRC=%RUST_SRC%\src
```

1.5) Intall xbuild

```
cargo install cargo-xbuild
```

3) Compile the rust library + EDKII

* `Repository` is the identifier of the repository the patch applies.
  This identifier should only be provided for repositories other than
  `edk2`. For example `edk2-BuildSpecification` or `staging`.
* `Branch` is the identifier of the branch the patch applies. This
  identifier should only be provided for branches other than `edk2/master`.
  For example `edk2/UDK2015`, `edk2-BuildSpecification/release/1.27`, or
  `staging/edk2-test`.
* `Module` is a short identifier for the affected code or documentation. For
  example `MdePkg`, `MdeModulePkg/UsbBusDxe`, `Introduction`, or
  `EDK II INF File Format`.
* `Brief-single-line-summary` is a short summary of the change.
* The entire first line should be less than ~70 characters.
* `Full-commit-message` a verbose multiple line comment describing
  the change.  Each line should be less than ~70 characters.
* `Signed-off-by` is the contributor's signature identifying them
  by their real/legal name and their email address.

# Submodules

Submodule in EDK II is allowed but submodule chain should be avoided
as possible as we can. Currently EDK II contains the following submodules

- CryptoPkg/Library/OpensslLib/openssl
- ArmPkg/Library/ArmSoftFloatLib/berkeley-softfloat-3

ArmSoftFloatLib is actually required by OpensslLib. It's inevitable
in openssl-1.1.1 (since stable201905) for floating point parameter
conversion, but should be dropped once there's no such need in future
release of openssl.

To get a full, buildable EDK II repository, use following steps of git
command

```
cargo xbuild [--release]
```

the output is target/[debug|release]/base_bmp_support_lib_rust.lib

2.4.2) For Windows OS:

Add binary location to PATH (Assume LLVM_SRC=<llvm-project> @REM modify to the llvm-project git.)

* clang and lld-link are at %LLVM_SRC%\build\Release\bin.

```
set LLVM_SRC=<llvm-project> @REM modify to the llvm-project git.
set PATH=%LLVM_SRC%\build\Release\bin;%PATH%
```

3) Prepare EDKII

Copy RustPkg/Override/BaseTools/Conf/build_rule.template to Conf/build_rule.txt.

Copy RustPkg/Override/BaseTools/Conf/tools_def.template to Conf/tools_def.txt.

Set CLANG7WIN_BIN variable to the binary path, if they are not in PATH.

Additional step for Windows, set CLANG_HOST_BIN=n for nmake.

```
set CLANG_HOST_BIN=n
```

4) Prebuild binary:

goto RustPkg\External\r-efi

```
cargo xbuild --release --target x86_64-unknown-uefi
cargo xbuild --target x86_64-unknown-uefi
cargo xbuild --release --target i686-unknown-uefi
cargo xbuild --target i686-unknown-uefi
```

## Build

Currently, we may use ways to build UEFI module with rust support.

1) Build the rust module with Cargo.

go to rust folder, such as RustPkg\Test\TestRustLangApp,
RustPkg\MdeModulePkg\Universal\CapsulePei

```
cargo xbuild [--release] --target [x86_64-unknown-uefi|i686-unknown-uefi]
```

the output is target/[x86_64-unknown-uefi|i686-unknown-uefi]/[debug|release]/test_rust_lang_app.efi

This only works for UEFI application.

2) Build the rust module with EDKII tools.

```
build -p RustPkg/RustPkg.dsc -t CLANG7WIN -a IA32 -a X64
```

We support below build combination:

2.1) C source + Rust source mixed in INF (Library or Module)

Rust source code is supported by EDKII build rule – Rust-To-Lib-File (.rs => .lib)

Limitation: Rust cannot have external dependency.

2.2) Pure Rust Module only.

A Cargo.toml file is added to INF file as source.

Rust Module build is supported by EDKII build rule – Toml-File.RUST_MODULE (Toml => .efi)

Limitation: Runtime might be a problem, not sure about virtual address translation for rust internal global variable.

2.3) Pure Rust Module + Pure Rust Library with Cargo Dependency.

Same as #2.

The cargo dependency means the rust lib dependency declared in Cargo.toml.

2.4) Pure Rust Module + C Library with EDKII Dependency.

Rust Module build is supported by EDKII build rule – Toml-File (Toml => .lib) 

The EDKII dependency means the EDKII lib dependency declared in INF.

If a rust module is built with C, the cargo must use staticlib. Or rlib should be used.

2.5) C Module + Pure Rust Library with EDKII Dependency.

Rust Lib build is supported by EDKII build rule – Toml-File. (Toml => .lib) 

2.6) Pure Rust Module + Pure Rust Library with EDKII Dependency.

Same as #4 + #5.

NOTE: Incremental build for Cargo.toml is supported. Updating .rs with cargo will trigger rebuild.

## TODO

* support cross module include.
* add more rust modules.

* The full LLVM enabling is out of scope of this task. It is handled by EDKII trunk.
