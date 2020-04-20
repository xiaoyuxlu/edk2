call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars64.bat"
netsh winhttp set proxy child-prc.intel.com:913
set https_proxy=http://child-prc.intel.com:913
call edksetup.bat
build -p OvmfPkg\OvmfPkgX64.dsc -a X64 -t VS2017

