/*
 * compat-windows.c
 *
 * host compatible code for windows.
 *
 * authors : 
 *     范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

cpumask_t cpu_online_map;
int nr_cpu_ids = 0;
u64 max_mdl_describe_length = 0;

u64 host_memory_size = 0;
u64 host_memory_highest_address = 0;

struct page** global_page_list = 0;

DEFINE_RAW_SPINLOCK(global_page_lock);
DEFINE_RAW_SPINLOCK(vmmr0_mmap_lock);
DEFINE_RAW_SPINLOCK(global_vmem_lock);
DEFINE_RAW_SPINLOCK(global_malloc_lock);

LIST_HEAD(vmmr0_mmap_list);
LIST_HEAD(global_vmem_list);
LIST_HEAD(global_physical_memory_map_list);
LIST_HEAD(global_malloc_list);


typedef struct vmmr0_preempt
{
	KIRQL irql;
	u64   count;
}vmmr0_preempt;

DEFINE_PER_CPU(struct vmmr0_preempt, vmmr0_preempt_per_cpu);

void preempt_disable(void)
{
/*
	if(__get_cpu_var(vmmr0_preempt_per_cpu).count == 0)
	{
		__get_cpu_var(vmmr0_preempt_per_cpu).irql = vmmr0_RaiseIrqlToDpcLevel();
	}
	__get_cpu_var(vmmr0_preempt_per_cpu).count++;
	*/
}

void preempt_enable(void)
{
	/*
	if(__get_cpu_var(vmmr0_preempt_per_cpu).count == 0)
	{
		return;
	}
	vmmr0_LowerIrql(__get_cpu_var(vmmr0_preempt_per_cpu).irql);
	__get_cpu_var(vmmr0_preempt_per_cpu).count--;
	*/
}

struct smp_function_context
{
	void (_cdecl *func)(void *info);
	void *info;
	int cpu;
};

DEFINE_PER_CPU(struct smp_function_context, smp_function_cpu);

ULONG_PTR NTAPI smp_function_caller(IN ULONG_PTR p)
{
	struct smp_function_context *sfc = (struct smp_function_context*)p;
	if(sfc->cpu == smp_processor_id())
	{
		sfc->func(sfc->info);
	}
	return (ULONG_PTR)0;
}

ULONG_PTR NTAPI vcpu_kick_intr(IN ULONG_PTR p)
{
	return (ULONG_PTR)0;
}

int vmmr0_smp_call_function_single(int cpu, void (*func)(void *info),
				 void *info, int wait)
{
#ifdef VMMR0_REAL_SMP_CALL
	per_cpu(smp_function_cpu, cpu).func = func;
	per_cpu(smp_function_cpu, cpu).info = info;
	per_cpu(smp_function_cpu, cpu).cpu = cpu;
    KeIpiGenericCall(smp_function_caller, (ULONG_PTR)&per_cpu(smp_function_cpu, cpu));
#else
	//1 set thread affinity
	//2 call func
	//3 reset old affinity
	KAFFINITY old_affinity;
	KAFFINITY new_affinity;
	KIRQL irql = KeGetCurrentIrql();
	KIRQL irql_dummy;
	new_affinity = BIT(cpu);
	int irql_lowerd = 0;
	if(irql > PASSIVE_LEVEL)
	{
		KeLowerIrql(PASSIVE_LEVEL);
		irql_lowerd = 1;
	}
	old_affinity = KeSetSystemAffinityThreadEx(new_affinity);


	func(info);

	KeSetSystemAffinityThreadEx(old_affinity);

	if(irql_lowerd)
	{
		KeRaiseIrql(irql, &irql_dummy);
	}
	return 0;
#endif
}

unsigned int get_processor_num(void)
{
#ifdef CONFIG_X86_64
	return KeQueryActiveProcessorCount(0);
#else
	return KeNumberProcessors;
#endif
}

unsigned int get_processor_num_affinity(PKAFFINITY aff)
{
#ifdef CONFIG_X86_64
	return KeQueryActiveProcessorCount(aff);
#else
	return 0;
#endif
}

#ifndef CONFIG_64BIT
/* 64bit divisor, dividend and result. dynamic precision */
uint64_t div64_u64(uint64_t dividend, uint64_t divisor)
{
	uint32_t high, d;

	high = divisor >> 32;
	if (high)
	{
		unsigned int shift = fls(high);

		d = divisor >> shift;
		dividend >>= shift;
	}
	else
	{
		d = divisor;
	}

	do_div(dividend, d);

	return dividend;
}
#endif
/*
 * smp_call_function_mask() is not defined/exported below 2.6.24 on all
 * targets and below 2.6.26 on x86-64
 */

struct vmmr0_call_data_struct
{
	void (*func) (void *info);
	void *info;
	atomic_t started;
	atomic_t finished;
	int wait;
};

static void vmmr0_ack_smp_call(void *_data)
{
	struct vmmr0_call_data_struct *data = _data;
	/* if wait == 0, data can be out of scope
	 * after atomic_inc(info->started)
	 */
	void (*func) (void *info) = data->func;
	void *info = data->info;
	int wait = data->wait;

	smp_mb();
	atomic_inc(&data->started);
	(*func)(info);
	if (wait)
	{
		smp_mb();
		atomic_inc(&data->finished);
	}
}

int vmmr0_smp_call_function_mask(cpumask_t mask,
			       void (*func) (void *info), void *info, int wait)
{
	struct vmmr0_call_data_struct data;
	cpumask_t allbutself;
	int cpus;
	unsigned long cpu;
	int me;
	unsigned long offset;

	unsigned long cpu_num;

	cpu_num = get_processor_num();
	data.func = func;
	data.info = info;
	atomic_set(&data.started, 0);
	data.wait = wait;
	if (wait)
	{
		atomic_set(&data.finished, 0);
	}

	for_each_set_bit(cpu, (unsigned long*)&mask, cpu_num)
	{
		smp_call_function_single(cpu, vmmr0_ack_smp_call, &data, 0);
	}
out:
	return 0;
}

void vmmr0_smp_send_reschedule(int cpu)
{
	//too expensive, hack it?
	KeIpiGenericCall(vcpu_kick_intr, (ULONG_PTR)NULL);
}


#ifndef CONFIG_USER_RETURN_NOTIFIER

DEFINE_PER_CPU(struct vmmr0_user_return_notifier *, vmmr0_urn);

#endif /* CONFIG_USER_RETURN_NOTIFIER */

void *bsearch(const void *key, const void *base, size_t num, size_t size,
	      int (*cmp)(const void *key, const void *elt))
{
	size_t start = 0, end = num;
	int result;

	while (start < end)
	{
		size_t mid = start + (end - start) / 2;

		result = cmp(key, base + mid * size);
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return (void *)base + mid * size;
	}

	return NULL;
}

void* kmemdup(void* src, unsigned long len, unsigned long flag)
{
	void *dst = NULL;
	if(!src)
	{
		return (void* )(-ENOMEM);
	}
	dst = kmalloc(len, flag);
	if (!dst)
	{
		return (void* )(-ENOMEM);
	}
	memcpy(dst, src, len);
	return dst;
}

static void u32_swap(void *a, void *b, int size)
{
	u32 t = *(u32 *)a;
	*(u32 *)a = *(u32 *)b;
	*(u32 *)b = t;
}

static void generic_swap(void *a, void *b, int size)
{
	char t;

	do
	{
		t = *(char *)a;
		*(char *)a++ = *(char *)b;
		*(char *)b++ = t;
	} while (--size > 0);
}

void sort(void *base, size_t num, size_t size,
	  int (*cmp_func)(const void *, const void *),
	  void (*swap_func)(void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num/2 - 1) * size, n = num * size, c, r;

	if (!swap_func)
	{
		swap_func = (size == 4 ? u32_swap : generic_swap);
	}

	/* heapify */
	for ( ; i >= 0; i -= size)
	{
		for (r = i; r * 2 + size < n; r  = c)
		{
			c = r * 2 + size;
			if (c < n - size && cmp_func(base + c, base + c + size) < 0)
			{
				c += size;
			}
			if (cmp_func(base + r, base + c) >= 0)
			{
				break;
			}
			swap_func(base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i > 0; i -= size)
	{
		swap_func(base, base + i, size);
		for (r = 0; r * 2 + size < i; r = c)
		{
			c = r * 2 + size;
			if (c < i - size && cmp_func(base + c, base + c + size) < 0)
			{
				c += size;
			}
			if (cmp_func(base + r, base + c) >= 0)
			{
				break;
			}
			swap_func(base + r, base + c, size);
		}
	}
}

static void init_kernel_version_vars()
{
	ULONG major_version = 0;
	ULONG minor_version = 0;
	ULONG build_number  = 0;
	RTL_OSVERSIONINFOW kernel_version;
	RtlGetVersion(&kernel_version);
	major_version = kernel_version.dwMajorVersion;
	minor_version = kernel_version.dwMinorVersion;
	build_number = kernel_version.dwBuildNumber;

	if (major_version == 6 && minor_version == 0)
	{
		max_mdl_describe_length = gigabytes(2) - PAGE_SIZE;
		//Vista or Windows Server 2008
	}
	else if (major_version == 6 &&  minor_version == 1)
	{
		max_mdl_describe_length = gigabytes(4) - PAGE_SIZE;
		//Windows 7 or Windows Server 2008 R2
	}
	else if (major_version == 6 &&  minor_version == 2)
	{
		max_mdl_describe_length = gigabytes(4) - PAGE_SIZE;
		//Windows 8 or Windows Server 2012
	}
	else if (major_version > 6)
	{
		max_mdl_describe_length = gigabytes(4) - PAGE_SIZE;
		//later
	}
	else
	{
		//older
		max_mdl_describe_length = PAGE_SIZE * (65535 - sizeof(MDL)) / sizeof(ULONG_PTR);
	}
}

typedef struct physical_memory_map
{
	u64 start_address;
	u64 length;
	struct list_head list;
}physical_memory_map;

#define REG_KEY_PHYS_MEM  L"\\Registry\\Machine\\Hardware\\ResourceMap\\System Resources\\Physical Memory"
#define REG_VAL_PHYS_MEM  L".Translated"

int get_physical_memory_map(void)
{
	int mode = 0;
	int type = 0;
	u64 addr = 0;
	u64 size = 0;
	u64 sig_type = 0;
	u64 size_total = 0;
	u32 bus_count = 0;
    u32 res_count = 0;
	u32 index = 0;
	u8* key_data = 0;

	ULONG size_read = 0;
	UNICODE_STRING key_name;
	UNICODE_STRING value_name;
	HANDLE hkey;
	NTSTATUS status;
	PKEY_VALUE_PARTIAL_INFORMATION pkvpi;
	OBJECT_ATTRIBUTES  object_attributes;

	RtlInitUnicodeString(&key_name, REG_KEY_PHYS_MEM);
	RtlInitUnicodeString(&value_name, REG_VAL_PHYS_MEM);

	struct physical_memory_map* physical_memory_map = 0;

	InitializeObjectAttributes(&object_attributes, &key_name,
              OBJ_CASE_INSENSITIVE, NULL, NULL);


	status = ZwOpenKey(&hkey, GENERIC_ALL, &object_attributes);
	if (!NT_SUCCESS(status))
	{
		printk("vmmr0: open reg failed\n");
		goto out_error;
	}

	status = ZwQueryValueKey(hkey, &value_name,
            KeyValuePartialInformation, NULL, 0, &size_read);

	if (status == STATUS_OBJECT_NAME_NOT_FOUND || size_read == 0)
	{
		ZwClose(hkey);
		printk("vmmr0: reg not exist\n");
		goto out_error;
	}

	pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(NonPagedPool, size_read);
	if(!pkvpi)
	{
		printk("vmmr0: allocate mem for PKEY_VALUE_PARTIAL_INFORMATION error\n");
		goto out_error;
	}

	status = ZwQueryValueKey(hkey, &value_name,
			KeyValuePartialInformation, pkvpi, size_read, &size_read);

	if(sizeof(void*) == 4)
	{
		mode = 32;
	}
	else
	{
		mode = 64;
	}
	key_data = (unsigned char*)pkvpi->Data;
	bus_count = *(u32*)key_data;
	if(bus_count != 1)
	{
		printk("vmmr0: bus_count != 1\n");
		goto out_error;
	}
	res_count = *(u32*)(key_data + 16);
	key_data += 20;
	sig_type= *(u32*)(key_data);
	key_data += 4;

	printk("vmmr0: host`s physical memory map: \n");
	for(index = 0; index < res_count; index++)
	{
		if(sig_type == 0x103)
		{
			type = 32;
		}
		else
		{
			type = 64;
		}
		addr = *(u64*)(key_data);
		key_data += 8;
		if(mode != 32)
		{
			size = *(u64*)(key_data);
			if(type == 64)
			{
				size <<= 8;
			}
			key_data += 8;
		}
		else
		{
			size = *(u32*)(key_data);
			key_data += 4;
		}
		sig_type = *(u32*)(key_data);
		key_data += 4;
		physical_memory_map = ExAllocatePool(NonPagedPool, sizeof(*physical_memory_map));
		if(!physical_memory_map)
		{
			printk("vmmr0: allocate mem for physical_memory_map error, index = %d\n", index);
			goto out_error;
		}
		physical_memory_map->start_address = addr;
		physical_memory_map->length = size;
		list_add_tail(&physical_memory_map->list, &global_physical_memory_map_list);
		printk("vmmr0: start addr = %llx, size = %llx\n", addr, size);
		size_total += size;
		host_memory_highest_address = (host_memory_highest_address < (addr + size)) ? (addr + size) : host_memory_highest_address;
	}
	host_memory_size = size_total;
	printk("vmmr0: host`s physical memory size: %llx highest address: %llx\n", host_memory_size, host_memory_highest_address);
	ZwClose(hkey);
	ExFreePool(pkvpi);
	return 0;

	out_error:
	return -1;
}

int init_windows_runtime(void)
{
	int i;
	int r;
	u64 tmp64 = 0;
	
	init_per_cpu_win();
	init_kernel_version_vars();
	init_boot_cpu_data();

	r = get_physical_memory_map();
	if(r)
	{
		goto out_error;
	}
	raw_spin_lock_init(&global_page_lock);
	raw_spin_lock_init(&vmmr0_mmap_lock);
	raw_spin_lock_init(&global_vmem_lock);

	vmmr0_tsc_khz = get_tsc_khz();
	printk("vmmr0: get_tsc_khz: vmmr0_tsc_khz = %d\n", vmmr0_tsc_khz);

	for(i = 0; i < NR_CPUS; i++)
	{
		cpu_tsc_khz[i] = vmmr0_tsc_khz;
	}

	for(i = 0; i < NR_CPUS; i++)
	{
		vmmr0_preempt_per_cpu[i].count = 0;
		vmmr0_preempt_per_cpu[i].irql = PASSIVE_LEVEL;
	}
	tmp64 = (host_memory_highest_address >> PAGE_SHIFT) * sizeof(struct page*);
	global_page_list = (struct page**)ExAllocatePool(NonPagedPool, tmp64);
	if(!global_page_list)
	{
		r = -1;
		goto out_error;
	}
	memset(global_page_list, 0, tmp64);
	
	return 0;

	out_error:
	return r;
}

void uninit_windows_runtime(void)
{
	struct list_head* i, *n;
	struct physical_memory_map* physical_memory_map = 0;
	list_for_each_safe(i, n, &global_physical_memory_map_list)
	{
		physical_memory_map = list_entry(i, struct physical_memory_map, list);
		list_del(&physical_memory_map->list);
		ExFreePool(physical_memory_map);
	}
	ExFreePool(global_page_list);

	//at last..
	destoy_malloc_rec();
}

//both mingw and winddk do not have these funcs in their lib. but some funcs deal with irql need these.
u64 __readcr8(void)
{
	u64 ret = 0;
	__asm__ volatile("mov %%cr8, %0": "=r"(ret));
	return ret;
}

void __writecr8(u64 val)
{
	__asm__ volatile("mov %0, %%cr8": :"r"(val));
}

void vmmr0_timer_dpc_fn(struct _KDPC *Dpc, 
						PVOID DeferredContext, 
						PVOID SystemArgument1, 
						PVOID SystemArgument2)
{
	struct hrtimer *timer = (struct hrtimer*)DeferredContext;
	enum hrtimer_restart ret = timer->function(timer);
	if(ret == HRTIMER_RESTART)
	{
		vmmr0_hrtimer_restart(timer);
	}
	else if(ret == HRTIMER_NORESTART)
	{
	}
	else
	{
	}
}

void hrtimer_init(struct hrtimer *timer, clockid_t clock_id, enum hrtimer_mode mode)
{
	KeInitializeTimerEx(&timer->ktimer, SynchronizationTimer);
	timer->base = &timer->base_hack;
	timer->base->get_time = ktime_get;
	KeInitializeDpc(&timer->kdpc, (PKDEFERRED_ROUTINE)vmmr0_timer_dpc_fn, timer);
}

int hrtimer_start(struct hrtimer *timer, ktime_t tim, const enum hrtimer_mode mode)
{
	int r;
	if(mode == HRTIMER_MODE_ABS)
	{
		//timer->due_time.QuadPart = (ktime_to_ns(ktime_get()) - ktime_to_ns(tim)) / 100;
		timer->due_time.QuadPart = ktime_to_ns(tim);
		timer->node.expires = tim;
		timer->_softexpires = tim;
	}
	else if (mode == HRTIMER_MODE_REL)
	{
		timer->due_time.QuadPart = 0LL - (s64)(ktime_to_ns(tim));
		timer->node.expires = ktime_add(tim, ktime_get());
		timer->_softexpires = ktime_add(tim, ktime_get());
	}
	else
	{
		r = 0;
		printk("vmmr0: hrtimer_start: invalid mode\n");
		goto out;
	}
	do_div(timer->due_time.QuadPart, 100);
	r = (int)KeSetTimer(&timer->ktimer, timer->due_time, &timer->kdpc);
out:
	return r;
}

int hrtimer_cancel(struct hrtimer *timer)
{
	int r;
	r = KeCancelTimer(&timer->ktimer);
	return r;
}

int vmmr0_hrtimer_restart(struct hrtimer* timer)
{
	int r;
	//timer->due_time.QuadPart = (ktime_to_ns(ktime_get()) - ktime_to_ns(timer->node.expires)) / 100;
	timer->due_time.QuadPart = ktime_to_ns(timer->node.expires);
	do_div(timer->due_time.QuadPart, 100);
	r = (int)KeSetTimer(&timer->ktimer, timer->due_time, &timer->kdpc);
	return r;
}

static void process_one_work(struct workqueue_struct *wq, struct work_struct *work)
{
	HANDLE h;
	list_del_init(&work->entry);
	
	work_func_t f = work->func;
	f(work);
	work->wq = 0;
}

void vmmr0_workqueue_thread_fn(void* p)
{
	struct workqueue_struct* wq = (struct workqueue_struct *)p;
	struct work_struct *work = 0;
	
	while (!wq->exit_request)
	{
		KeWaitForSingleObject(&wq->do_work_pending, Executive, KernelMode, FALSE, NULL);
		spin_lock(&wq->work_lock);
		
		while (!list_empty(&wq->work_list))
		{
			if (wq->modify_work_pending)
			{
				break;
			}
			work = list_first_entry(&wq->work_list,
						struct work_struct, entry);
			process_one_work(wq, work);
		}
		spin_unlock(&wq->work_lock);
	}
	KeSetEvent(&wq->can_exit, IO_NO_INCREMENT, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}