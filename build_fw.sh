#!/bin/bash

#rm -rf /c/work/edk2/Build/OvmfX64/DEBUG_VS2017/FV/
./build_fw.bat
echo "scp /c/work/edk2/Build/OvmfX64/DEBUG_VS2017/FV/OVMF.fd luxy@xiaoyu-dev:/home/luxy/test/OVMF_fat.fd"
scp /c/work/edk2/Build/OvmfX64/DEBUG_VS2017/FV/OVMF.fd luxy@xiaoyu-dev:/home/luxy/test/OVMF_fat.fd
