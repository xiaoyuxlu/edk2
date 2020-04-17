qemu-system-x86_64 -s -m 2048 -bios OVMF_fat.fd --nographic -debugcon file:debug.log -global isa-debugcon.iobase=0x402 -drive if=none,id=virtio-disk0,file=clear-31380-kvm.img -device virtio-blk-pci,drive=virtio-disk0  -hda fat:rw:hda-content

 kill -9 `ps aux | grep qemu-system-x86_64 | sed -n "1, 1p" | awk '{print $2}'`
