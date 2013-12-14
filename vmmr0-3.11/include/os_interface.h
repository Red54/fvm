/*
 * os_interface.h
 *
 *  Created on: 2011-8-1
 *      Author: fw1
 */

#ifndef OS_INTERFACE_H_
#define OS_INTERFACE_H_

//#define VMMR0_DEBUG
//#define VMMR0_RDTSC_EXIT
#define VMMR0_MMU_PTE_PREFETCH
#define VMMR0_MAX_VCPU_NUM 254
#define KVM_SOFT_MAX_VCPUS 160
#define KVM_MEMORY_SLOTS 32
/* memory slots that does not exposed to userspace */
#define KVM_PRIVATE_MEM_SLOTS 4
#define KVM_MEM_SLOTS_NUM (KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)

#define KVM_MMIO_SIZE 16

#define KVM_PIO_PAGE_OFFSET 1

#ifndef CONFIG_KVM_APIC_ARCHITECTURE
#define CONFIG_KVM_APIC_ARCHITECTURE
#endif

#ifndef CONFIG_HAVE_KVM_MSI
#define CONFIG_HAVE_KVM_MSI 1
#endif

#ifndef CONFIG_KVM_MMIO
#define CONFIG_KVM_MMIO
#endif

#ifdef CONFIG_KVM_MMIO
#define KVM_COALESCED_MMIO_PAGE_OFFSET 2
#endif

#include "../vmmr0-config.h"

#define VMMR0_DEFAULT_PERF_TIMES    0x10000

#ifdef VMMR0_DEBUG
#define kdprint printk

#define perf_mon_start(TIMES) \
	static u64 starttime = 0; \
	static u64 stoptime = 0;  \
	static u64 alltime = 0;   \
	static u64 times = 0;     \
	times++;                  \
	if (times >= TIMES) {     \
		printk("vmmr0: %s run %lld times cost %lld cycles\n", __func__, times, alltime); \
		times = 0;            \
		alltime = 0;          \
	}                         \
	rdtscll(starttime);       \

#define perf_mon_stop()       \
	rdtscll(stoptime);        \
	alltime += stoptime - starttime;\


#else
#define kdprint(x, ...)

#define perf_mon_start(TIMES)
#define perf_mon_stop()

#endif

#ifdef HOST_LINUX

#define HOST_LINUX_OPTIMIZED
#define OS_LINUX_OPTIMIZED_MM
#define OS_LINUX_OPTIMIZED_PID
#define OS_LINUX_OPTIMIZED_MMU_AUDIT
#define CONFIG_HAVE_PMU
#define CONFIG_HAVE_ASSIGNED_DEV

#define VMMR0_ENABLE_SHARED_MSR
#define VMMR0_ENABLE_KVM_HYPERV


#ifndef HOST_LINUX_OPTIMIZED
#undef CONFIG_HAVE_KVM_EVENTFD
#undef CONFIG_HAVE_KVM_IRQCHIP
#undef CONFIG_IOMMU_API
#endif

#ifdef OS_LINUX_OPTIMIZED_MM
#define KVM_ARCH_WANT_MMU_NOTIFIER
#endif

#if !defined(CONFIG_HAVE_KVM_EVENTFD) && defined(HOST_LINUX_OPTIMIZED)
#define CONFIG_HAVE_KVM_EVENTFD 1
#define CONFIG_HAVE_KVM_IRQCHIP 1
#endif

#if !defined(CONFIG_KVM_ASYNC_PF) && defined(HOST_LINUX_OPTIMIZED)
#define CONFIG_KVM_ASYNC_PF 1
#endif

#include "linux_types.h"

#include <linux/compiler.h>
#include <linux/version.h>

#include <linux/cpumask.h>
#include <linux/irq_work.h>
#include <linux/ioctl.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
#include <linux/kconfig.h>
#endif
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/anon_inodes.h>
#include <linux/profile.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <linux/uaccess.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mmu_context.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/user.h>
#include <asm/xsave.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/eventfd.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/smp.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/stat.h>
#include <linux/iommu.h>
#include <linux/intel-iommu.h>
#include <linux/hrtimer.h>
#include <linux/spinlock.h>
#include <linux/math64.h>
#include <linux/atomic.h>
#include <linux/ratelimit.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <linux/cpufreq.h>
#include <linux/hash.h>
#include <linux/mmu_notifier.h>
#include <linux/hardirq.h>
#include <linux/rcupdate.h>
#include <linux/ratelimit.h>
#include <linux/delay.h>

#include <asm/signal.h>
#include <asm/types.h>
#include <asm/msidef.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/apicdef.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/cmpxchg.h>
#include <asm/io.h>
#include <asm/mce.h>
#include <asm/xcr.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/pvclock.h>
#include <asm/div64.h>
#include <asm/pvclock-abi.h>
#include <asm/msr-index.h>

#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/compat.h>
#include <linux/hugetlb.h>
#include <linux/syscalls.h>
#include <linux/dmar.h>
#include <linux/perf_event.h>
#include <linux/tboot.h>
#include <linux/user-return-notifier.h>
#include <linux/context_tracking.h>
#include <asm/i387.h>
#include <asm/mtrr.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,00)
#include <asm/fpu-internal.h>
#endif

#include "compat-linux.h"


#endif //HOST_LINUX

#ifdef HOST_WINDOWS

#include <ddk/ntddk.h>

//#define WIN32
//#define WIN64
#if !defined(WIN64) && !defined(WIN32)
#error neither WIN64 nor WIN32 is defined!
#endif

#ifdef WIN64
#ifndef __x86_64__
#define __x86_64__
#endif
#ifndef CONFIG_X86_64
#define CONFIG_X86_64 1
#endif
#endif


#if defined(WIN32) && !defined(WIN64)
#ifndef __i386__
#define __i386__
#endif
#ifndef CONFIG_X86_32
#define CONFIG_X86_32 1
#endif
#endif

#ifdef CONFIG_X86_64
#define CONFIG_64BIT
#ifndef __x86_64
#define __x86_64__
#endif
#elif defined(CONFIG_X86_32)
#define CONFIG_32BIT
#ifndef __i386__
#define __i386__
#endif
#else
#error unsupported target!
#endif

#define gigabytes(x)    (u64)((u64)x*1024ULL*1024ULL*1024ULL)
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define VMMR0_REAL_SMP_CALL

#define CONFIG_HAVE_ASSIGNED_DEV
#define CONFIG_HAVE_KVM_EVENTFD 1
#define CONFIG_HAVE_KVM_IRQCHIP 1

#include "windows_types.h"

#include "make_gcc_happy.h"


#include "cpu_features.h"

#define printk 					DbgPrint
#define printk2(x, ...) 		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, x, ##__VA_ARGS__)
#define pr_err 					printk
#define pr_debug 				printk
#define pr_info_ratelimited 	printk
#define pr_warn_ratelimited 	printk
#define pr_debug_ratelimited	printk

#include "paging.h"
#include "list.h"
#include "mm.h"
#include "error_def.h"
#include "cpu_flag.h"
#include "bitmap.h"
#include "cpu_mask.h"
#include "per_cpu_win.h"
#include "segment.h"
#include "desc.h"
#include "apicdef.h"
#include "call_seh.h"
#include "msidef.h"

#define __always_inline inline

#define KERN_EMERG
#define KERN_ALERT
#define KERN_CRIT
#define KERN_ERR
#define KERN_WARNING
#define KERN_NOTICE
#define KERN_INFO
#define KERN_DEBUG

#define MSEC_PER_SEC	1000L
#define USEC_PER_MSEC	1000L
#define NSEC_PER_USEC	1000L
#define NSEC_PER_MSEC	1000000L
#define USEC_PER_SEC	1000000L
#define NSEC_PER_SEC	1000000000L
#define FSEC_PER_SEC	1000000000000000LL

#define VM_FAULT_SIGBUS	0x0002


//TODO:IOW/R
#define _IO(a, b)       	CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define _IOR(a, b, c)       CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define _IOW(a, b, c)       CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define _IOWR(a, b, c)      CTL_CODE(FILE_DEVICE_UNKNOWN,b,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)

#define rcu_dereference(p) p

#define might_sleep()
#define dump_stack();


#include "compat-windows.h"
#include "pow2.h"


#endif

//some common headers...
#include "get_cpu_x.h"

#endif /* OS_INTERFACE_H_ */
