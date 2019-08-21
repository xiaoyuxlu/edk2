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

1) Install rust (https://www.rust-lang.org/)
toolchain: x86_64-pc-windows-msvc, i686-pc-windows-msvc, x86_64-unknown-uefi.
version: nigtly

2) Intall xbuild

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

Currently, we may use 3 ways to build UEFI module with rust support.
Finally, we want to reduce the supported ways.

1) Build the rust module with Cargo.

go to rust folder, such as RustPkg\Test\TestRustLangApp,
RustPkg\MdeModulePkg\Universal\CapsulePei

```
cargo xbuild [--release] --target x86_64-unknown-uefi
```

the output is target/x86_64-unknown-uefi/[debug|release]/test_rust_lang_app.efi

2) Include the rust file in INF, and build with EDKII.

goto RustPkg\External\r-efi
```
cargo xbuild --release --target x86_64-pc-windows-msvc
cargo xbuild --target x86_64-pc-windows-msvc
cargo xbuild --release --target i686-pc-windows-msvc
cargo xbuild --target i686-pc-windows-msvc
```

build a normal EFI module, such as RustPkg/Test/TestRustLangApp2/TestRustLangApp.inf,
RustPkg/MdeModulePkg/Universal/CapsulePei/CapsuleX64.inf,
RustPkg/MdeModulePkg/Library/BaseBmpSupportLib/BaseBmpSupportLib.inf

NOTE:
If the rust file has dependency, .toml file is required and .toml file should be included in INF.
If the rust file is standalone, .rs file can be included in INF.

3) build the rust module with Cargo as library, include binary lib in INF and build with EDKII

go to rust folder, such as RustPkg\MdeModulePkg\Library\BaseBmpSupportLibRust

```
cargo xbuild [--release] --target x86_64-pc-windows-msvc
```

the output is target/[debug|release]/base_bmp_support_lib_rust.lib

Then build the RustPkg/RustPkg.dsc, to generate TestBmpApp.efi.

## TODO

* support build in linux.
* support cross module include.
* add more rust version modules.
