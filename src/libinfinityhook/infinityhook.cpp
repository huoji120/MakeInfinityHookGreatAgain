/*
*	Module Name:
*		infinityhook.cpp
*
*	Abstract:
*		The implementation details of infinity hook.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "infinityhook.h"
#include "img.h"
#include "mm.h"
#include "../kinfinityhook/helpers.h"

//
// Used internally for IfhpModifyTraceSettings.
//
enum CKCL_TRACE_OPERATION
{
	CKCL_TRACE_START,
	CKCL_TRACE_SYSCALL,
	CKCL_TRACE_END
};

//
// To enable/disable tracing on the circular kernel context logger.
//
typedef struct _CKCL_TRACE_PROPERIES: EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

static BOOLEAN IfhpResolveSymbols();

static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation);

static ULONG64 IfhpInternalGetCpuClock();

//
// Works from Windows 7+. You can backport this to Vista if you
// include an OS check and add the Vista appropriate signature.
//
UCHAR EtwpDebuggerDataPattern[] = 
{ 
	0x2c, 
	0x08, 
	0x04, 
	0x38, 
	0x0c 
};

//
// _WMI_LOGGER_CONTEXT.GetCpuClock.
//
#define OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK 0x28

//
// _KPCR.Prcb.RspBase.
//
#define OFFSET_KPCR_RSP_BASE 0x1A8

//
// _KPCR.Prcb.CurrentThread.
//
#define OFFSET_KPCR_CURRENT_THREAD 0x188

//
// _KTHREAD.SystemCallNumber.
//
#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x80

//
// EtwpDebuggerData silos.
//
#define OFFSET_ETW_DEBUGGER_DATA_SILO 0x10

//
// The index of the circular kernel context logger.
//
#define INDEX_CKCL_LOGGER 2

//
// Magic values on the stack. We use this to filter out system call 
// exit events.
//
#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

static bool IfhpInitialized = false;
static INFINITYHOOKCALLBACK IfhpCallback = NULL;

static const void* EtwpDebuggerData = NULL;
static PVOID CkclWmiLoggerContext = NULL;
static PVOID SystemCallEntryPage = NULL;
/*
typedef NTSTATUS(NTAPI* PFHalpTimerQueryHostPerformanceCounter)(ULONG64* pTime);
PFHalpTimerQueryHostPerformanceCounter OldPtrOff140C009E0 = 0;
*/
typedef __int64(*PFHvlGetQpcBias)();
PFHvlGetQpcBias OldPtrOff140C009E0 = 0;

ULONG64 PtrOff140C009E0 = 0;
ULONG64 HvlpReferenceTscPage = 0;
NTSTATUS UtilSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	NT_ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	__try
	{
		for (ULONG_PTR i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (ULONG_PTR j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}

			if (found != FALSE)
			{
				*ppFound = (PUCHAR)base + i;
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNHANDLED_EXCEPTION;
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS UtilScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	NT_ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_INVALID_PARAMETER;

	ULONG SizeOfNt = 0;
	PVOID base = ImgGetBaseAddress(NULL, &SizeOfNt);
	if (!base)
		return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
			return UtilSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, ppFound);
	}

	return STATUS_NOT_FOUND;
}
extern "C" __int64 HookHvlGetQpcBias()
{
	//__debugbreak();
	if (ExGetPreviousMode() != KernelMode)
	{
		IfhpInternalGetCpuClock();
	}
	return *((ULONG64*)(*((ULONG64*)HvlpReferenceTscPage)) + 3);
}
/*
extern "C" __int64 __fastcall HookHalpTimerQueryHostPerformanceCounter(ULONG64 * pTime)
{
	if (ExGetPreviousMode() != KernelMode)
	{
		//__debugbreak();
		IfhpInternalGetCpuClock();
	}
	
	return OldPtrOff140C009E0(pTime);
}
*/
/*
*	Initialize infinity hook: executes your user defined callback on 
*	each syscall. You can extend this functionality to do other things
*	like trap on page faults, context switches, and more... This demo
*	only does syscalls.
*/
NTSTATUS IfhInitialize(_In_ 
	INFINITYHOOKCALLBACK InfinityHookCallback)
{
	if (IfhpInitialized)
	{
		return STATUS_ACCESS_DENIED;
	}

	//
	// Let's assume CKCL session is already started (which is the 
	// default scenario) and try to update it for system calls only.
	//
	NTSTATUS Status = IfhpModifyTraceSettings(CKCL_TRACE_SYSCALL);
	if (!NT_SUCCESS(Status))
	{
		//
		// Failed... let's try to turn it on.
		//
		Status = IfhpModifyTraceSettings(CKCL_TRACE_START);

		//
		// Failed again... We exit here, but it's possible to setup
		// a custom logger instead and use SystemTraceProvider instead
		// of hijacking the circular kernel context logger.
		//
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
		
		Status = IfhpModifyTraceSettings(CKCL_TRACE_SYSCALL);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
	}	

	//
	// We need to resolve certain unexported symbols.
	//
	if (!IfhpResolveSymbols())
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	IfhpCallback = InfinityHookCallback;
	*reinterpret_cast<uintptr_t*>((uintptr_t)CkclWmiLoggerContext + OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK) = 2;
	
	// off_140C009E0 pattern
	//UCHAR pattern[] = "\x48\xcc\xcc\xcc\xcc\xcc\xcc\xE8\xcc\xcc\xcc\xcc\x83\xcc\xcc\x75\xcc\x38\xcc\xcc\xcc\xcc\xcc\x75\xcc\x48\xcc\xcc\xcc\xcc\xcc\xcc\x83\xB8\xcc\xcc\xcc\xcc\xcc\x0F\xcc\xcc\xcc\xcc\xcc";
	UCHAR pattern[] = "\x48\xcc\xcc\xcc\xcc\xcc\xcc\x48\x85\xC0\x74\xcc\x48\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x74\xcc\xE8\xcc\xcc\xcc\xcc\x48\x8B\xD8\x48\xcc\xcc\xcc\xcc\xcc\xcc\xE8\xcc\xcc\xcc\xcc\x48\x03\xD8\x48\x89\x1F\x33\xC0\xEB\xcc";
	NTSTATUS status = UtilScanSection(".text", (PCUCHAR)pattern, 0xCC, sizeof(pattern) - 1, (PVOID*)&PtrOff140C009E0);
	if (!NT_SUCCESS(status))
	{
		kprintf("[DebugMessAge] PtrOff140C009E0 not found! :( \n");
		return false;
	}


	UCHAR pattern_HvlpReferenceTscPage[] = "\x48\xcc\xcc\xcc\xcc\xcc\xcc\x48\x8B\xcc\xcc\x48\xcc\xcc\xcc\xcc\xcc\xcc\x48\xF7\xE2\x4C\x8B\xcc\xcc\x48\xcc\xcc\xcc\xcc\xcc\xcc\x49\x03\xD0\x48\x89\xcc\xcc\xcc\x8B\x08\x41\x3B\xC9\x75\xcc";
	status = UtilScanSection(".text", (PCUCHAR)pattern_HvlpReferenceTscPage, 0xCC, sizeof(pattern_HvlpReferenceTscPage) - 1, (PVOID*)&HvlpReferenceTscPage);
	if (!NT_SUCCESS(status))
	{
		kprintf("[DebugMessAge] HvlGetQpcBias not found! :( \n");
		return false;
	}
	HvlpReferenceTscPage = HvlpReferenceTscPage + *(ULONG*)(HvlpReferenceTscPage + 3) + 7;

	kprintf("[DebugMessAge] off_140C009E0 %p \n", PtrOff140C009E0);
	PtrOff140C009E0 = PtrOff140C009E0 + *(ULONG*)(PtrOff140C009E0 + 3) + 7;
	//OldPtrOff140C009E0 = (PFHalpTimerQueryHostPerformanceCounter)(*((ULONG64*)PtrOff140C009E0));
	OldPtrOff140C009E0 = (PFHvlGetQpcBias)(*((ULONG64*)PtrOff140C009E0));
	//*((ULONG64*)PtrOff140C009E0) = (ULONG64)HookHalpTimerQueryHostPerformanceCounter;
	*((ULONG64*)PtrOff140C009E0) = (ULONG64)HookHvlGetQpcBias;


	IfhpInitialized = true;

	return STATUS_SUCCESS;
}

/*
*	Disables and then re-enables the circular kernel context logger,
*	clearing the system of the infinity hook pointer override.
*/
void IfhRelease()
{
	if (!IfhpInitialized)
	{
		return;
	}

	if (NT_SUCCESS(IfhpModifyTraceSettings(CKCL_TRACE_END)))
	{
		IfhpModifyTraceSettings(CKCL_TRACE_START);
	}
	*((UINT64*)PtrOff140C009E0) = (UINT64)OldPtrOff140C009E0;
	IfhpInitialized = false;
}

/*
*	Resolves necessary unexported symbols.
*/
static BOOLEAN IfhpResolveSymbols()
{
	//
	// We need to resolve nt!EtwpDebuggerData to get the current ETW
	// sessions WMI_LOGGER_CONTEXTS, find the CKCL, and overwrite its
	// GetCpuClock function pointer.
	//
	PVOID NtBaseAddress = NULL;
	ULONG SizeOfNt = 0;
	NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOfNt);
	if (!NtBaseAddress)
	{
		return FALSE;
	}

	ULONG SizeOfSection;
	PVOID SectionBase = ImgGetImageSection(NtBaseAddress, ".data", &SizeOfSection);
	if (!SectionBase)
	{
		return FALSE;
	}

	//
	// Look for the EtwpDebuggerData global using the signature. This 
	// should be the same for Windows 7+.
	//
	EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
	if (!EtwpDebuggerData)
	{
		//
		// Check inside of .rdata too... this is true for Windows 7.
		// Thanks to @ivanpos2015 for reporting.
		//
		SectionBase = ImgGetImageSection(NtBaseAddress, ".rdata", &SizeOfSection);
		if (!SectionBase)
		{
			return FALSE;
		}

		EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
		if (!EtwpDebuggerData)
		{
			return FALSE;
		}
	}

	// 
	// This is offset by 2 bytes due to where the signature starts.
	//
	EtwpDebuggerData = (PVOID)((uintptr_t)EtwpDebuggerData - 2);
	
	//
	// Get the silos of EtwpDebuggerData.
	//
	PVOID* EtwpDebuggerDataSilo = *(PVOID**)((uintptr_t)EtwpDebuggerData + OFFSET_ETW_DEBUGGER_DATA_SILO);

	//
	// Pull out the circular kernel context logger.
	//
	CkclWmiLoggerContext = EtwpDebuggerDataSilo[INDEX_CKCL_LOGGER];

	//
	// Grab the system call entry value.
	//
	SystemCallEntryPage = PAGE_ALIGN(ImgGetSyscallEntry());
	if (!SystemCallEntryPage)
	{
		return FALSE;
	}

	return TRUE;
}

/*
*	Modify the trace settings for the circular kernel context logger.
*/
static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation)
{
	PCKCL_TRACE_PROPERTIES Property = (PCKCL_TRACE_PROPERTIES)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!Property)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	memset(Property, 0, PAGE_SIZE);

	Property->Wnode.BufferSize = PAGE_SIZE;
	Property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	Property->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
	Property->Wnode.Guid = CkclSessionGuid;
	Property->Wnode.ClientContext = 1;
	Property->BufferSize = sizeof(ULONG);
	Property->MinimumBuffers = Property->MaximumBuffers = 2;
	Property->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

	NTSTATUS Status = STATUS_ACCESS_DENIED;
	ULONG ReturnLength = 0;

	//
	// Might be wise to actually hook ZwTraceControl so folks don't 
	// disable your infinity hook ;).
	//
	switch (Operation)
	{
		case CKCL_TRACE_START:
		{
			Status = ZwTraceControl(EtwpStartTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
		case CKCL_TRACE_END:
		{
			Status = ZwTraceControl(EtwpStopTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
		case CKCL_TRACE_SYSCALL:
		{
			//
			// Add more flags here to trap on more events!
			//
			Property->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

			Status = ZwTraceControl(EtwpUpdateTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
	}

	ExFreePool(Property);

	return Status;
}

/*
*	We replaced the GetCpuClock pointer to this one here which 
*	implements stack walking logic. We use this to determine whether 
*	a syscall occurred. It also provides you a way to alter the 
*	address on the stack to redirect execution to your detoured
*	function.
*	
*/
static ULONG64 IfhpInternalGetCpuClock()
{
	//
	// Extract the system call index (if you so desire).
	//
	PKTHREAD CurrentThread = (PKTHREAD)__readgsqword(OFFSET_KPCR_CURRENT_THREAD);
	unsigned int SystemCallIndex = *(unsigned int*)((uintptr_t)CurrentThread + OFFSET_KTHREAD_SYSTEM_CALL_NUMBER);

	PVOID* StackMax = (PVOID*)__readgsqword(OFFSET_KPCR_RSP_BASE);
	PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();

	//
	// First walk backwards on the stack to find the 2 magic values.
	//
	for (PVOID* StackCurrent = StackMax; 
		StackCurrent > StackFrame;
		--StackCurrent)
	{
		// 
		// This is intentionally being read as 4-byte magic on an 8
		// byte aligned boundary.
		//
		PULONG AsUlong = (PULONG)StackCurrent;
		if (*AsUlong != INFINITYHOOK_MAGIC_1)
		{
			continue;
		}

		// 
		// If the first magic is set, check for the second magic.
		//
		--StackCurrent;

		PUSHORT AsShort = (PUSHORT)StackCurrent;
		if (*AsShort != INFINITYHOOK_MAGIC_2)
		{
			continue;
		}

		//
		// Now we reverse the direction of the stack walk.
		//
		for (;
			StackCurrent < StackMax;
			++StackCurrent)
		{
			PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;

			if (!(PAGE_ALIGN(*AsUlonglong) >= SystemCallEntryPage && 
				PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)SystemCallEntryPage + (PAGE_SIZE * 2))))
			{
				continue;
			}

			//
			// If you want to "hook" this function, replace this stack memory 
			// with a pointer to your own function.
			//
			void** SystemCallFunction = &StackCurrent[9];

			if (IfhpCallback)
			{
				IfhpCallback(SystemCallIndex, SystemCallFunction);
			}

			break;
		}

		break;
	}

	return __rdtsc();
}