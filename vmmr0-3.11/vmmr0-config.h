#define KERNEL_EXTRAVERSION 

#define HOST_WINDOWS
#ifdef HOST_LINUX
#define HOST_LONG_SIZE 8
#else
#ifdef HOST_WINDOWS
#define HOST_LONG_SIZE 4
#endif //HOST_WINDOWS
#endif //HOST_LINUX
#ifndef HOST_LONG_SIZE
#error "HOST_LONG_SIZE undefined!"
#endif
