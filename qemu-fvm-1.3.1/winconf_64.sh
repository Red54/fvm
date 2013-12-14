bash configure --enable-sdl --audio-drv-list=sdl --target-list=x86_64-softmmu --enable-kvm --enable-vnc \
	--extra-cflags="-I /e/mingwbuild/qemu-fvm-1.3.1/linux-headers"
rm -rf ./linux-headers/asm
cp -rf ./linux-headers/asm-x86 ./linux-headers/asm
rm -rf ./pixman
cp -rf ./pixman_win64 ./pixman
