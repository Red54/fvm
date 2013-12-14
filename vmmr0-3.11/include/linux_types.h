/*
 * linux_types.h
 *
 *      Author: fw1
 */

#ifndef LINUX_TYPES_H_
#define LINUX_TYPES_H_

#define MAKE_DATA_TYPE(X,Y) (X##Y)

//LP64/32 data model.
#define VMMR0_LPU(X) MAKE_DATA_TYPE(X,U)
#define VMMR0_LPL(X) MAKE_DATA_TYPE(X,L)
#define VMMR0_LPLL(X) MAKE_DATA_TYPE(X,LL)
#define VMMR0_LPUL(X) MAKE_DATA_TYPE(X,UL)
#define VMMR0_LPULL(X) MAKE_DATA_TYPE(X,ULL)



#endif /* LINUX_TYPES_H_ */
