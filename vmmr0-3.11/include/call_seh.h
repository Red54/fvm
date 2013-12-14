/*
 * call_seh.h
 *
 */

#ifndef CALL_SEH_H_
#define CALL_SEH_H_


typedef void (*seh_fn)(void* p);


int call_seh(seh_fn fn, void* p);


#endif /* CALL_SEH_H_ */
