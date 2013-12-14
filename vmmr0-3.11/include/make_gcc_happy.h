/*
 * make_gcc_happy.h
 * some definitions and functions to make gcc happy.(windows)
 */

#ifndef MAKE_GCC_HAPPY_H_
#define MAKE_GCC_HAPPY_H_

#define VM_BUG_ON(cond) do { (void)(cond); } while (0)

#define WARN_ON(x)
#define BUG_ON(x)
#define BUG()

#define noinline
#define __init
#define __exit
#define __user
#define __read_mostly
#define __acquires(x)
#define __releases(x)
#define __acquire(x) (void)0
#define __release(x) (void)0

#define uninitialized_var(x) x
#define mark_tsc_unstable(x)

#define LOCK_PREFIX_HERE

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#ifndef FASTCALL
#define FASTCALL(x)	x
#define fastcall
#endif

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
(type *)( (char *)__mptr - offsetof(type,member) );})

#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))


#define barrier() __asm__ __volatile__("": : :"memory")

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define ALTERNATIVE(oldinstr, newinstr, feature)			\
									\
      "661:\n\t" oldinstr "\n662:\n"					\
      "	 .long 661b - .\n"			/* label           */	\
      "	 .long 663f - .\n"			/* new instruction */	\
      "	 .word " __stringify(feature) "\n"	/* feature bit     */	\
      "	 .byte 662b-661b\n"			/* sourcelen       */	\
      "	 .byte 664f-663f\n"			/* replacementlen  */	\
      "	 .byte 0xff + (664f-663f) - (662b-661b)\n" /* rlen <= slen */	\
      "663:\n\t" newinstr "\n664:\n"		/* replacement     */


#define alternative(oldinstr, newinstr, feature)			\
	asm volatile (ALTERNATIVE(oldinstr, newinstr, feature) : : : "memory")


#ifdef CONFIG_X86_32
/*#define mb() alternative("lock; addl $0,0(%%esp)", "mfence", X86_FEATURE_XMM2)
#define rmb() alternative("lock; addl $0,0(%%esp)", "lfence", X86_FEATURE_XMM2)
#define wmb() alternative("lock; addl $0,0(%%esp)", "sfence", X86_FEATURE_XMM)*/
#define mb() asm volatile("mfence":::"memory")
#define rmb() asm volatile("lfence":::"memory")
#define wmb() asm volatile("sfence" ::: "memory")
#else
#define mb() asm volatile("mfence":::"memory")
#define rmb() asm volatile("lfence":::"memory")
#define wmb() asm volatile("sfence" ::: "memory")
#endif

#define smp_mb() mb()
#define smp_rmb() rmb()
#define smp_wmb() wmb()

#define smp_mb__after_atomic_inc smp_mb
#define smp_mb__before_atomic_dec smp_mb

void preempt_disable(void);
void preempt_enable(void);

#define asmlinkage __attribute__((regparm(0)))

static inline void vmmr0_synchronize_srcu_expedited(struct srcu_struct *sp) { }

static inline int vmmr0_init_srcu(void) {return 0;}
static inline void vmmr0_exit_srcu(void) {}

static inline void vmmr0_clock_warn_suspend_bug(void) {}

#endif /* MAKE_GCC_HAPPY_H_ */
