/*
 * windows_types.h
 *
 *      Author: fw1
 */

#ifndef WINDOWS_TYPES_H_
#define WINDOWS_TYPES_H_

#include "../vmmr0-config.h"
#include <ddk/ntddk.h>


typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

typedef unsigned long long u64;
typedef signed long long s64;

typedef unsigned long long __u64;
typedef signed long long __s64;

#define MAKE_DATA_TYPE(X,Y) (X##Y)

#ifdef CONFIG_X86_64
//LP64 data model.
#define long long long
#define VMMR0_LPU(X) MAKE_DATA_TYPE(X,U)
#define VMMR0_LPL(X) MAKE_DATA_TYPE(X,LL)
#define VMMR0_LPLL(X) MAKE_DATA_TYPE(X,LL)
#define VMMR0_LPUL(X) MAKE_DATA_TYPE(X,ULL)
#define VMMR0_LPULL(X) MAKE_DATA_TYPE(X,ULL)
#else
//LP32 data model.
#define VMMR0_LPU(X) MAKE_DATA_TYPE(X,U)
#define VMMR0_LPL(X) MAKE_DATA_TYPE(X,L)
#define VMMR0_LPLL(X) MAKE_DATA_TYPE(X,LL)
#define VMMR0_LPUL(X) MAKE_DATA_TYPE(X,UL)
#define VMMR0_LPULL(X) MAKE_DATA_TYPE(X,ULL)
#endif

typedef unsigned long sigset_t;
typedef unsigned long pteval_t;
typedef unsigned long ulong;


typedef int __sig_atomic_t;
typedef int sig_atomic_t;

typedef u8 uint8_t;
typedef u16 uint16_t;
typedef u32 uint32_t;
typedef u64 uint64_t;

typedef s8 int8_t;
typedef s16 int16_t;
typedef s32 int32_t;
typedef s64 int64_t;

typedef u64 natural_width;
typedef u64 gfp_t;

#ifndef bool
typedef int bool;
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

typedef struct rcu_head
{
	struct rcu_head *next;
	void (*func)(struct rcu_head *head);
}rcu_head;

typedef struct srcu_struct
{
	KIRQL old_irql;
	int raised;
}srcu_struct;

typedef struct file
{
	void* private_data;
}file;

typedef struct vm_fault
{

}vm_fault;

typedef struct vm_area_struct
{

}vm_area_struct;

typedef struct mm_struct
{

}mm_struct;

typedef struct task_struct
{

}task_struct;

typedef struct pt_regs
{

}pt_regs;

typedef struct atomic_t
{
	volatile int counter;
}atomic_t;

typedef struct raw_spinlock_t
{
	KSPIN_LOCK spin_lock;
	KIRQL old_irql;
}raw_spinlock_t;

typedef struct spinlock_t
{
	KSPIN_LOCK spin_lock;
	KIRQL old_irql;
}spinlock_t;

#define DEFINE_RAW_SPINLOCK(x) \
 		raw_spinlock_t x;

#define DECLARE_RAW_SPINLOCK(x) \
 		extern raw_spinlock_t x;

#define DEFINE_SPINLOCK(x) \
		spinlock_t x;

#define DECLARE_SPINLOCK(x) \
		extern spinlock_t x;

static inline void raw_spin_lock_init(raw_spinlock_t *lock)
{
	KeInitializeSpinLock(&lock->spin_lock);
}

static inline void raw_spin_lock(raw_spinlock_t *lock)
{
	KeAcquireSpinLock(&lock->spin_lock, &lock->old_irql);
}

static inline void raw_spin_unlock(raw_spinlock_t *lock)
{
	KeReleaseSpinLock(&lock->spin_lock, lock->old_irql);
}

static inline void spin_lock_init(spinlock_t *lock)
{
	KeInitializeSpinLock(&lock->spin_lock);
}

static inline void spin_lock(spinlock_t *lock)
{
	KeAcquireSpinLock(&lock->spin_lock, &lock->old_irql);
}

static inline void spin_unlock(spinlock_t *lock)
{
	KeReleaseSpinLock(&lock->spin_lock, lock->old_irql);
}

static inline void cond_resched_lock(spinlock_t *lock)
{
}

typedef struct mutex
{
	FAST_MUTEX mutex;
}mutex;

static inline void mutex_init(struct mutex *lock)
{
	ExInitializeFastMutex(&lock->mutex);
}

static inline void mutex_lock(struct mutex *lock)
{
	ExAcquireFastMutex(&lock->mutex);
}

static inline void mutex_unlock(struct mutex *lock)
{
	ExReleaseFastMutex(&lock->mutex);
}

#endif /* WINDOWS_TYPES_H_ */


