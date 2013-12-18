bash configure --enable-sdl --audio-drv-list=sdl --target-list=x86_64-softmmu --enable-kvm --enable-vnc \
	--extra-cflags="-I /e/mingwbuild/qemu-fvm-1.7.0/linux-headers"
rm -rf ./linux-headers/asm
cp -rf ./linux-headers/asm-x86 ./linux-headers/asm
