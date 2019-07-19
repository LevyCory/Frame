/**********************************************************************************************************************
	File Name	:	wincommon.h
	Author		:	Cory Levy
	Created		:	10/03/2019 @ 21:03
	Description	:	Common macros and constants.
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include <windows.h>
#include <process.h>

/** Macros ***********************************************************************************************************/

/**********************************************************************************************************************
	Macro		:	__CLOSE_OBJECT
	Purpose		:	A sub-macro for closing kernel objects.
	Parameters	:	@ object - The object to close.
					@ value - The default invalid value for that object.
					@ callback - The closing function for that object
**********************************************************************************************************************/
#define __CLOSE_OBJECT(object, value, callback)																		\
{																													\
	if ((value) != (object))																						\
	{																												\
		(VOID)(callback)(object);																					\
		(object) = (value);																							\
	}																												\
}

/**********************************************************************************************************************
	Macro		:	CLOSE_HANDLE
	Purpose		:	Safely closes a handle.
	Parameters	:	@ handle - The handle to close.
**********************************************************************************************************************/
#define CLOSE_HANDLE(handle) __CLOSE_OBJECT(handle, NULL, CloseHandle)

/**********************************************************************************************************************
	Macro		:	CLOSE_FILE
	Purpose		:	Safely closes a FILE.
	Parameters	:	@ file - The handle to close.
**********************************************************************************************************************/
#define CLOSE_FILE(file) __CLOSE_OBJECT(file, INVALID_HANDLE_VALUE, CloseHandle)

/**********************************************************************************************************************
	Macro		:	FREE_LIBRARY
	Purpose		:	Safely frees a library.
	Parameters	:	@ library - The library to free.
**********************************************************************************************************************/
#define FREE_LIBRARY(library) __CLOSE_OBJECT(library, NULL, FreeLibrary)

/**********************************************************************************************************************
	Macro		:	HEAPALLOC
	Purpose		:	Allocates size bytes on the heap. The memory is guaranteed to be zeroed.
	Parameters	:	@ size - Size of buffer to allocate in bytes.
**********************************************************************************************************************/
#define HEAPALLOC(size) (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size)))

/**********************************************************************************************************************
	Macro		:	HEAPALLOC
	Purpose		:	Allocates 'size' elements of type 'type' on the heap.
	Parameters	:	@ size - Size of buffer to allocate in bytes.
					@ type - The type of the array to allocate.
**********************************************************************************************************************/
#define HEAPALLOC_ARRAY(type, size) (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(type) * (size)))

/**********************************************************************************************************************
	Macro		:	HEAPFREE
	Purpose		:	Frees heap-allocated buffers.
	Parameters	:	@ handle - The memory handle to free.
**********************************************************************************************************************/
#define HEAPFREE(handle)																							\
{																													\
	if (NULL != (handle))																								\
	{																												\
		(VOID)HeapFree(GetProcessHeap(), 0, (handle));																\
		(handle) = NULL;																							\
	}																												\
}

/**********************************************************************************************************************
	Macro		:	ARRAY_SIZE
	Purpose		:	Return the size of a stack allocated array.
	Parameters	:	@ array - The array to perform the calculation on.
**********************************************************************************************************************/
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

/**********************************************************************************************************************
	Macro		:	ASSERT
	Purpose		:	Invokes breakpoint if the condition is false.
	Parameters	:	@ expression - The expression to evaluate.
**********************************************************************************************************************/
#ifdef _DEBUG
#define ASSERT(expression) if(!(expression)) { __debugbreak(); }
#else
#define ASSERT(expression) 
#endif

/**********************************************************************************************************************
	Macro		:	NOTNULL
	Purpose		:	Assert that the parameter is not null.
**********************************************************************************************************************/
#define NOTNULL(parameter) ASSERT(NULL != (parameter))

/**********************************************************************************************************************
	Macro		:	__in_req
	Purpose		:	SAL annotation to denote both __in and __notnull.
**********************************************************************************************************************/
#define __in_req __in __notnull

/**********************************************************************************************************************
	Macro		:	BEGINTHREADEX
	Purpose		:	Makes _beginthreadex behave like CreateThread.
	Parameters	:	See CreateThread on MSDN.
**********************************************************************************************************************/
#define BEGINTHREADEX(ptSecurity, cbStackSize, pfnStartAddr, pvParam, dwCreateFlags, pdwThreadID)					\
	((HANDLE) _beginthreadex(																						\
		(PVOID)(ptSecurity),																						\
		(unsigned)(cbStackSize),																					\
		(_beginthreadex_proc_type)(pfnStartAddr),																	\
		(PVOID)(pvParam),																							\
		(unsigned)(dwCreateFlags),																					\
		(unsigned*)(pdwThreadID)))

/**********************************************************************************************************************
	Macro		:	STRING_CCH
	Purpose		:	Returns the length of a string in characters. Works both for normal strings and wide strings.
	Parameters	:	@length[in] - The length of the string.
**********************************************************************************************************************/
#define STRING_CCH(length) ((length) * sizeof(TCHAR))

/**********************************************************************************************************************
	Macro		:	ADD_POINTERS
	Purpose		:	Adds two pointers together.
	Parameters	:	
**********************************************************************************************************************/
#define ADD_POINTERS(first, second) (PVOID)((SIZE_T)(first) + (SIZE_T)(second))

/**********************************************************************************************************************
	Macro		:	ADD_POINTERS
	Purpose		:	Adds two pointers together.
	Parameters	:	
**********************************************************************************************************************/
#define SUB_POINTERS(first, second) (PVOID)((SIZE_T)(first) - (SIZE_T)(second))
