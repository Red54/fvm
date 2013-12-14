fvm (cross-platform kvm)
===

Fvm is a cross-platform kvm, it supports Windows & Linux host so far.

	qemu-fvm is a customized version of qemu, like qemu-kvm.
	
	vmmr0 is a kernel module (driver) to accelerate qemu.

How to Build :

	On Linux Host, build it like kvm.
	
	On Windows Host (only support windows kernel version > 7600, amd64 architecture):
	
	
	1. Build qemu-fvm :
		1) checkout source code.
		2) modify winconf_64.sh :
			modify this config
				--extra-cflags="-I /(path to qemu-fvm)/linux-headers"
				eg : --extra-cflags="-I /e/mingwbuild/qemu-fvm-1.3.1/linux-headers"
		3) download a mingw-w64 env (there is a mingw-w64 with gcc 4.7 is my github).
		4) in mingw shell, execute:
			sh winconf_64.sh
			make
	2. Build vmmr0 :
		1) checkout source code.
		2) modify winconf_64.sh :
			modify these configs
				--mingw_lib_path="(path to mingw64)\mingw\lib" 
				--mingw_include_path="(path to mingw64)\x86_64-w64-mingw32\include\ddk"
				eg : 
					--mingw_lib_path="D:\mingw64\mingw\lib" 
					--mingw_include_path="D:\mingw64\x86_64-w64-mingw32\include\ddk"
		3) download a mingw-w64 env with gcc 4.8(there is a mingw-w64 with gcc 4.8 is my github).
			!!! mingw gcc 4.7 cannot compile vmmr0 perfectly, please use mingw gcc 4.8.
		4) in mingw shell, execute:
			sh winconf_64.sh
			make


How To Use :

	To use fvm for linux, please checkout the code and compile fvm.
	
	To use fvm for windows, we should follow these steps:
	
	You should have a computer installed 64-bit windows 7 or higher.
	
	1. enable  'Lock pages in memory' of current user in gpedit.msc:
		http://msdn.microsoft.com/en-us/library/ms190730.aspx
		fvm use awe memory in order to lock guest 's page. Windows kernel do not have anything like mmu_notifier    :(     
	
	2. windows x64 needs driver signing, so enable testmode.
	
		bcdedit -set testsigning on
	
	3. reboot your computer.
	
	4. install the vmmr0.sys kernel module as service named 'vmmr0' and start it.
	
		execute in cmd:
	
		sc create vmmr0 binpath="(path to vmmr0.sys)" type=kernel start=demand
		net start vmmr0
	
	5. all done! Let 's run kvm on windows.
		
		eg:
		
		create a bat file , and type these words:
		
		(path to fvm-x86_64w.exe)  -drive file=D:\vm\linux-0.2.img,cache=writeback -machine accel=kvm,kernel_irqchip=off -cpu qemu64,-vmx -smp sockets=1,cores=1 -m 128 -soundhw hda -net nic,model=e1000 -net user -rtc base=localtime -vga vmware
		
		Save and run this bat as admin.

Enjoy!

Known problems:
	
	1. do not use vmware vga card if the guest is Ubuntu 12.04, or the qemu (version 1.3 )will core.
	
	2. The mouse auto switching while running linux guests (Ubuntu, etc.) can not work. And the qemu will lost 	response. Please use vnc to run Ubuntu.

