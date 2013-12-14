/*
 * mm.h
 *
 */

#include <linux/vmmr0_types.h>
#include "bit_defs.h"
#include "call_seh.h"

#ifndef MM_H_
#define MM_H_

#define GFP_KERNEL   BIT(0)
#define GFP_ATOMIC   BIT(1)
#define GFP_DMA      BIT(2)
#define __GFP_ZERO   BIT(3)
#define __GFP_DMA32  BIT(4)
#define GFP_UNALLOC  BIT(5)

enum vmmr0_pool_type
{
	pt_paged,
	pt_nonpaged,
	pt_pagedzero,
	pt_nonpagedzero,
	pt_dma32,
	pt_dma32zero,
	pt_unalloc,
	pt_unknown
};

#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask), 0)

#define get_page(x)
#define put_page(x)

typedef struct page
{
	void* hva;
	void* kmap_hva;
	unsigned long private;
	hpa_t hpa;
	pfn_t pfn;
	unsigned long gfp_mask;
	struct list_head list;
	PEPROCESS proc;
}page;

extern u64 host_memory_highest_address;
extern struct page** global_page_list;
DECLARE_RAW_SPINLOCK(global_page_lock);

#define page_private(page)			((page)->private)
#define set_page_private(page, v)	((page)->private = (v))

#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr), 0)

#define clear_page(page)	memset((page), 0, PAGE_SIZE)

#define kmap_atomic __kmap_atomic
#define kunmap_atomic __kunmap_atomic
#define vmmr0_kmap_atomic __kmap_atomic
#define vmmr0_kunmap_atomic __kunmap_atomic

#define virt_to_page(kaddr)	pfn_to_page((__pa(kaddr) >> PAGE_SHIFT))


static inline unsigned long gfp_mask_to_pool_type(unsigned long gfp_mask)
{
	int if_nonpaged = 0, if_zero = 0, if_dma32 = 0;

	if(gfp_mask & GFP_UNALLOC)
	{
		return pt_unalloc;
	}

	if(gfp_mask & GFP_KERNEL)
	{
		if_nonpaged = 0;
	}
	if(gfp_mask & GFP_ATOMIC || gfp_mask & GFP_DMA)
	{
		if_nonpaged = 1;
	}
	if(gfp_mask & __GFP_DMA32)
	{
		if_dma32 = 1;
	}
	if(gfp_mask & __GFP_ZERO)
	{
		if_zero = 1;
	}

	if(if_dma32)
	{
		if(if_zero)
		{
			return pt_dma32zero;
		}
		else
		{
			return pt_dma32;
		}
	}

	if(if_nonpaged)
	{
		if(if_zero)
		{
			return pt_nonpagedzero;
		}
		else
		{
			return pt_nonpaged;
		}
	}
	else
	{
		if(if_zero)
		{
			return pt_pagedzero;
		}
		else
		{
			return pt_paged;
		}
	}
	return pt_unknown;
}

typedef struct malloc_rec
{
	void* hva;
	struct list_head list;
}malloc_rec;

extern struct list_head global_malloc_list;
DECLARE_RAW_SPINLOCK(global_malloc_lock);

static inline int add_malloc_rec(void* hva)
{
	struct malloc_rec* malloc_rec;
	malloc_rec = ExAllocatePool(NonPagedPool, sizeof(*malloc_rec));
	if(!malloc_rec)
	{
		return -1;
	}
	malloc_rec->hva = hva;

	raw_spin_lock(&global_malloc_lock);
	list_add_tail(&malloc_rec->list, &global_malloc_list);
	raw_spin_unlock(&global_malloc_lock);
	return 0;
}

static inline int del_malloc_rec(void* hva)
{
	int r = -1;
	struct malloc_rec* malloc_rec;
	struct list_head* i, *n;

	raw_spin_lock(&global_malloc_lock);
	list_for_each_safe(i, n, &global_malloc_list)
	{
		malloc_rec = list_entry(i, struct malloc_rec, list);
		if (malloc_rec->hva == hva)
		{
			list_del(&malloc_rec->list);
			ExFreePool(malloc_rec);
			r = 0;
			goto out;
		}
	}
	out:
	raw_spin_unlock(&global_malloc_lock);
	return r;
}

static inline void destoy_malloc_rec(void)
{
	struct malloc_rec* malloc_rec;
	struct list_head* i, *n;

	raw_spin_lock(&global_malloc_lock);
	list_for_each_safe(i, n, &global_malloc_list)
	{
		malloc_rec = list_entry(i, struct malloc_rec, list);
		list_del(&malloc_rec->list);
		ExFreePool(malloc_rec);
	}
	raw_spin_unlock(&global_malloc_lock);
}

static inline void *kmalloc(size_t size, unsigned long flags)
{
	void* ret = 0;
	int if_zero = 0;

	switch(gfp_mask_to_pool_type(flags))
	{
	case pt_pagedzero:
	case pt_nonpagedzero:
	case pt_dma32zero:
		if_zero = 1;
		//pass through
	case pt_paged:
		//in kmalloc, pass through
	case pt_nonpaged:
		ret = ExAllocatePool(NonPagedPool, size);
		break;
	case pt_dma32:
		//not supported
	default:
		printk("vmmr0: kmalloc: error flags: %d\n", flags);
		break;
	}
	if(if_zero)
	{
		memset(ret, 0, size);
	}
	if(add_malloc_rec(ret))
	{
		printk("vmmr0: kmalloc: error add_malloc_rec\n");
		ExFreePool(ret);
		ret = 0;
	}
	return ret;
}

static inline void *kzalloc(size_t size, unsigned long flags)
{
	return kmalloc(size, flags | __GFP_ZERO);
}

static inline void kfree(void* hva)
{
	if(del_malloc_rec(hva))
	{
		kdprint("vmmr0: try to kfree invalid hva: %llx\n", hva);
	}
	else
	{
		ExFreePool(hva);
	}
}

static inline void *vmalloc(size_t size)
{
	void* ret = 0;
	ret = ExAllocatePool(NonPagedPool, size);
	if(add_malloc_rec(ret))
	{
		printk("vmmr0: kmalloc: error add_malloc_rec\n");
		ExFreePool(ret);
		ret = 0;
	}
	return ret;
}

static inline void vfree(void* hva)
{
	if(del_malloc_rec(hva))
	{
		kdprint("vmmr0: try to vfree invalid hva: %llx\n", hva);
	}
	else
	{
		ExFreePool(hva);
	}
}

static inline void *vzalloc(unsigned long size)
{
	void *addr = vmalloc(size);
	if (addr)
	{
		memset(addr, 0, size);
	}
	return addr;
}

static inline void *kmalloc_fast(size_t size, unsigned long flags)
{
	void* ret = 0;
	int if_zero = 0;

	switch(gfp_mask_to_pool_type(flags))
	{
	case pt_pagedzero:
	case pt_nonpagedzero:
	case pt_dma32zero:
		if_zero = 1;
		//pass through
	case pt_paged:
		//in kmalloc, pass through
	case pt_nonpaged:
		ret = ExAllocatePool(NonPagedPool, size);
		break;
	case pt_dma32:
		//not supported
	default:
		printk("vmmr0: kmalloc: error flags: %d\n", flags);
		break;
	}
	if(if_zero)
	{
		memset(ret, 0, size);
	}
	return ret;
}

static inline void *kzalloc_fast(size_t size, unsigned long flags)
{
	return kmalloc_fast(size, flags | __GFP_ZERO);
}

static inline void kfree_fast(void* hva)
{
	ExFreePool(hva);
}

#define VERIFY_READ		0
#define VERIFY_WRITE	1

static inline int access_ok(int type, unsigned long addr, unsigned long size)
{
	PHYSICAL_ADDRESS addr_phy;
	int valid = 1;
	unsigned long i = 0;

	return 1;
	for(;i < size; i++)
	{
		addr_phy = MmGetPhysicalAddress((PVOID)(addr + i));
		if(addr_phy.QuadPart == 0)
		{
			valid = 0;
			break;
		}
		if(!MmIsAddressValid((PVOID)(addr + i)))
		{
			valid = 0;
			break;
		}
	}
	return valid;
}

static inline pfn_t page_to_pfn(struct page* page)
{
	return page->pfn;
}

static inline void* page_to_hva(struct page* page)
{
	return page->hva;
}

static inline hpa_t page_to_phys(struct page* page)
{
	return page->hpa;
}

static inline struct page* pfn_to_page(pfn_t pfn)
{
	return global_page_list[pfn];
}

static inline hpa_t __pa(void* va)
{
	PHYSICAL_ADDRESS addr_phys;
	addr_phys = MmGetPhysicalAddress(va);
	return (hpa_t)(addr_phys.QuadPart);
}

static inline void* __va(hpa_t pa)
{
	void* ret = 0;
	ret = page_to_hva(pfn_to_page(pa >> PAGE_SHIFT));
	if(!ret)
	{
		printk("vmmr0: __va: invalid hpa %p\n", pa);
	}
	return ret;
}

static inline struct page *alloc_pages(unsigned int gfp_mask, unsigned int order)
{
	void* page_hva;
	unsigned long page_gfn;
	PHYSICAL_ADDRESS pageaddr_phys;
	PHYSICAL_ADDRESS addr_4g;
	int if_zero = 0;
	struct page* page = ExAllocatePool(NonPagedPool, sizeof(*page));
	if(!page)
	{
		printk("alloc_pages: nomem\n");
		goto out_error;
	}

	addr_4g.QuadPart = 4*1024ULL*1024ULL*1024ULL - PAGE_SIZE;    //DMA32, must under 4GB

	switch(gfp_mask_to_pool_type(gfp_mask))
	{
	case pt_pagedzero:
	case pt_nonpagedzero:
	case pt_dma32zero:
		if_zero = 1;
		//pass through
	case pt_paged:
		page_hva = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		break;
	case pt_nonpaged:
		page_hva = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		break;
	case pt_dma32:
		page_hva = MmAllocateContiguousMemory(PAGE_SIZE, addr_4g);
		break;
	default:
		printk("alloc_pages: error gfp_mask: %d\n", gfp_mask);
		break;
	}
	if(!page_hva)
	{
		printk("alloc_pages: nomem\n");
		goto out_error_free;
	}

	if((unsigned long)(page_hva) & 0xfffull)
	{
		printk("alloc_pages: allocated not aligined\n");
		goto out_error_free_hva;
	}

	if(if_zero)
	{
		memset(page_hva, 0, PAGE_SIZE);
	}

	pageaddr_phys = MmGetPhysicalAddress(page_hva);
	page->hpa = pageaddr_phys.QuadPart;
	page->pfn = page->hpa >> PAGE_SHIFT;
	page->hva = page_hva;
	page->gfp_mask = gfp_mask;
	page->proc = IoGetCurrentProcess();
	raw_spin_lock(&global_page_lock);
	global_page_list[page->pfn] = page;
	raw_spin_unlock(&global_page_lock);
	return page;

	out_error_free_hva:
	if(gfp_mask_to_pool_type(gfp_mask) == pt_dma32)
	{
		MmFreeContiguousMemory(page_hva);
	}
	else
	{
		ExFreePool(page_hva);
	}
	out_error_free:
	ExFreePool(page);
	out_error:
	return 0;
}

static inline void __free_pages(struct page* page, unsigned int order)
{
	switch(gfp_mask_to_pool_type(page->gfp_mask))
	{
	case pt_pagedzero:
	case pt_nonpagedzero:
	case pt_paged:
	case pt_nonpaged:
		ExFreePool(page->hva);
		break;
	case pt_dma32:
	case pt_dma32zero:
		MmFreeContiguousMemory(page->hva);
		break;
	case pt_unalloc:
		//wasnt allocated by me, just unmap and return
		MmUnmapIoSpace(page->hva, PAGE_SIZE);
		page->hva = 0;
		return;
		break;
	default:
		printk("__free_page: error gfp_mask: %d\n", page->gfp_mask);
		break;
	}
	raw_spin_lock(&global_page_lock);
	global_page_list[page->pfn] = 0;
	raw_spin_unlock(&global_page_lock);

	ExFreePool(page);
}

static inline void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0)
	{
		__free_pages(virt_to_page((void *)addr), order);
	}
}

static inline void* kmap(struct page* page)
{
	PHYSICAL_ADDRESS addr_phys;
	addr_phys.QuadPart = 0ull;
	addr_phys.QuadPart = page->hpa;
	page->kmap_hva = MmMapIoSpace(addr_phys, PAGE_SIZE, MmNonCached);
	return page->kmap_hva;
}

static inline void kunmap(struct page* page)
{
	MmUnmapIoSpace(page->kmap_hva, PAGE_SIZE);
	page->hva = 0;
}

static inline void* page_address(struct page* page)
{
	if(likely((unsigned long)page->hva))
	{
		return page->hva;
	}
	return kmap(page);
}

static inline void* get_zeroed_page(unsigned long gfp_mask)
{
	struct page* page = alloc_page(gfp_mask);
	memset(page->hva, 0, PAGE_SIZE);
	return page->hva;
}

static inline unsigned long __get_free_pages(unsigned long gfp_mask, unsigned int order)
{
	struct page *page;
	page = alloc_pages(gfp_mask, order);
	if (!page)
	{
		return 0;
	}
	return (unsigned long) page_address(page);
}

static inline int __get_user_pages_fast(unsigned long start, int nr_pages, int write, struct page **pages)
{
	int ret = nr_pages;
	while(nr_pages--)
	{
		pages[nr_pages] = virt_to_page((void*)(start + nr_pages * PAGE_SIZE));
	}
	return ret;
}

static inline int get_user_pages_fast(unsigned long start, int nr_pages, int write,
			struct page **pages)
{
	return __get_user_pages_fast(start, nr_pages, write, pages);
}

static inline unsigned long __clear_user(void *to, unsigned long n)
{
	memset((void *)to, 0, n);
	return 0;
}

static inline unsigned long clear_user(void *to, unsigned long n)
{
	if (access_ok(VERIFY_WRITE, (unsigned long)to, n))
	{
		n = __clear_user(to, n);
	}
	return n;
}

#define copy_to_user __copy_to_user
#define copy_from_user __copy_from_user
#define __copy_from_user_inatomic __copy_from_user

static inline int __copy_to_user(void *dst, const void *src, unsigned size)
{
	int if_re = 0;
	KIRQL oirql;
	KIRQL cirql = KeGetCurrentIrql();
	if(cirql > PASSIVE_LEVEL)
	{
		if_re = 1;
		KeLowerIrql(PASSIVE_LEVEL);
	}
	memcpy(dst, src, size);
	if(if_re)
	{
		KeRaiseIrql(cirql, &oirql);
	}
	return 0;
}

static inline int __copy_from_user(void *dst, const void *src, unsigned size)
{
	int if_re = 0;
	KIRQL oirql;
	KIRQL cirql = KeGetCurrentIrql();
	if(cirql > PASSIVE_LEVEL)
	{
		if_re = 1;
		KeLowerIrql(PASSIVE_LEVEL);
	}
	memcpy(dst, src, size);
	if(if_re)
	{
		KeRaiseIrql(cirql, &oirql);
	}
	return 0;
}

static inline void pagefault_disable(void)
{
	preempt_disable();
	barrier();
}

static inline void pagefault_enable(void)
{
	barrier();
	preempt_enable();
}

static inline void *__kmap_atomic(struct page *page)
{
	pagefault_disable();
	return page_address(page);
}

static inline void __kunmap_atomic(void *addr)
{
	pagefault_enable();
}

static inline void clean_user_pages(void)
{
	u64 index;
	struct page* page;
	PEPROCESS proc = IoGetCurrentProcess();
	for(index = 0; index < host_memory_highest_address >> PAGE_SHIFT; index++)
	{
		page = global_page_list[index];
		if(page)
		{
			if(page->proc == proc)
			{
				ExFreePool(page);
				global_page_list[index] = 0;
			}
		}
	}
}

static inline int set_user_pages(u64 addr_virt, u64 size)
{
	int r = 0;
	struct page* page;
	PHYSICAL_ADDRESS pageaddr_phys;
	u64 index;

	for(index = 0; index < size; index += PAGE_SIZE)
	{
		page = ExAllocatePool(NonPagedPool, sizeof(*page));
		if(!page)
		{
			goto out_error;
		}
		pageaddr_phys = MmGetPhysicalAddress((void*)(unsigned long)(addr_virt + index));
		page->hpa = pageaddr_phys.QuadPart;
		page->pfn = page->hpa >> PAGE_SHIFT;
		page->hva = (void*)(unsigned long)(addr_virt + index);
		page->gfp_mask = GFP_UNALLOC;
		page->proc = IoGetCurrentProcess();
		raw_spin_lock(&global_page_lock);
		global_page_list[page->pfn] = page;
		raw_spin_unlock(&global_page_lock);
	}
	return r;

	out_error:
	clean_user_pages();
	r = -1;
	return r;
}

#endif /* MM_H_ */
