
typedef void (*seh_fn)(void* p);


int call_seh(seh_fn fn, void* p)
{
	__try
	{	
		fn(p);
		return 0;
	}
	__except(1)
	{
		return -1;
	}
}