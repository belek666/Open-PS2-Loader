#ifndef _STDINT_H
#define _STDINT_H

// Incomplete

typedef signed char int8_t;
typedef unsigned char uint8_t;

typedef signed short int16_t;
typedef unsigned short uint16_t;

#ifdef _EE
typedef unsigned int uint32_t;
typedef unsigned long int uint64_t;
typedef unsigned int uint128_t __attribute__((mode(TI)));

typedef signed int int32_t;
typedef signed long int int64_t;
typedef signed int int128_t __attribute__((mode(TI)));

#else
typedef unsigned long int uint32_t;
typedef unsigned long long uint64_t;

typedef signed long int int32_t;
typedef signed long long int64_t;
#endif

#endif /* _STDINT_H */
