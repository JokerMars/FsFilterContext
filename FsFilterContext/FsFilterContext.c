/*++

Module Name:

    FsFilterContext.c

Abstract:

    This is the main module of the FsFilterContext miniFilter driver.

Environment:

    Kernel mode

--*/

#include "Common.h"
#include "Strategy.h"
#include "Context.h"


#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
PFILE_TYPE_PROCESS head;
ULONG offset;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FsFilterContextInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
FsFilterContextInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FsFilterContextInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
FsFilterContextUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FsFilterContextInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

//My designed protocol

FLT_PREOP_CALLBACK_STATUS
PreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
PostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
PreRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
PostRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);


ULONG GetProcessNameOffset();
PCHAR GetCurrentProcessName();


EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilterContextUnload)
#pragma alloc_text(PAGE, FsFilterContextInstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilterContextInstanceSetup)
#pragma alloc_text(PAGE, FsFilterContextInstanceTeardownStart)
#pragma alloc_text(PAGE, FsFilterContextInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{
		IRP_MJ_CREATE,
		0,
		PreCreate,
		PostCreate
	},

	{
		IRP_MJ_READ,
		0,
		PreRead,
		PostRead
	},

    { IRP_MJ_OPERATION_END }
};

CONST FLT_CONTEXT_REGISTRATION ContextNotifications[]=
{
	{
		FLT_STREAMHANDLE_CONTEXT,
		0,
		CleanupStreamHandleContext,
		sizeof(STREAM_HANDLE_CONTEXT),
		STREAM_HANDLE_CONTEXT_TAG
	},

	{FLT_CONTEXT_END}
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    ContextNotifications,                               //  Context
    Callbacks,                          //  Operation callbacks

    FsFilterContextUnload,                           //  MiniFilterUnload

    FsFilterContextInstanceSetup,                    //  InstanceSetup
    FsFilterContextInstanceQueryTeardown,            //  InstanceQueryTeardown
    FsFilterContextInstanceTeardownStart,            //  InstanceTeardownStart
    FsFilterContextInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
FsFilterContextInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterContext!FsFilterContextInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
FsFilterContextInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterContext!FsFilterContextInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
FsFilterContextInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterContext!FsFilterContextInstanceTeardownStart: Entered\n") );
}


VOID
FsFilterContextInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterContext!FsFilterContextInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

	DbgPrint("FsFilterContext!DriverEntry: Entered\n");

    //
    //  Register with FltMgr to tell it our callback routines
    //
	offset = GetProcessNameOffset();
	DbgPrint("Process name offset: %d", offset);

	PCHAR str = ".txt=notepad.exe,TxtReader.exe,;.jpg=ImageView.exe,explore.exe,;";

	head = GetStrategyFromString(str);
	OutputStrategy(head);


    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
FsFilterContextUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsFilterContext!FsFilterContextUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

	FreeStrategy(head);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/


FLT_PREOP_CALLBACK_STATUS
PreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS retVal = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retVal;
	}

	return retVal;
}






FLT_POSTOP_CALLBACK_STATUS
PostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	FLT_POSTOP_CALLBACK_STATUS retVal = FLT_POSTOP_FINISHED_PROCESSING;

	NTSTATUS status;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retVal;
	}


	//set the stream handle context
	PSTREAM_HANDLE_CONTEXT newCtx = NULL;
	status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&newCtx);
	if (!NT_SUCCESS(status))
	{
		status = FltAllocateContext(FltObjects->Filter, FLT_STREAMHANDLE_CONTEXT,
			sizeof(STREAM_HANDLE_CONTEXT), NonPagedPool, (PFLT_CONTEXT *)&newCtx);

		if (!NT_SUCCESS(status))
		{
			return retVal;
		}

		PFLT_CONTEXT oldCtx;
		status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS, newCtx, &oldCtx);
		if (oldCtx != NULL)
		{
			newCtx = (PSTREAM_HANDLE_CONTEXT)oldCtx;
		}
		if (!NT_SUCCESS(status))
		{
			return retVal;
		}
	}
	newCtx->ftp = NULL;
	newCtx->isEncrypted = FALSE;
	newCtx->isEncryptFileType = FALSE;



	//ONLY encrypt file type and secret process can go through;
	BOOLEAN isDir;
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);
	if (!NT_SUCCESS(status) || isDir)
	{
		return retVal;
	}

	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FltGetFileNameInformation error in PostCreate.");
		return retVal;
	}
	status = FltParseFileNameInformation(nameInfo);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FltParseFileNameInformation error in PostCreate");
		return retVal;
	}

	PFILE_TYPE_PROCESS current;
	if (!IsInStrategyList(head, &(nameInfo->Name), &current))
	{
		DbgPrint("It's not the encrypt file type.");
		return retVal;
	}
	DbgPrint("The encrypt file type: %wZ.", &(nameInfo->Name));

	PCHAR procName = GetCurrentProcessName();
	if (!IsSecretProcess(current, procName))
	{
		DbgPrint("It's not the process we are monitoring.");
		return retVal;
	}

	DbgPrint("It's the process: %s", procName);

	//set the context
	newCtx->ftp = current;
	newCtx->isEncrypted = FALSE;
	newCtx->isEncryptFileType = TRUE;

	status = FltQueryInformationFile(FltObjects->Instance, Data->Iopb->TargetFileObject,
		&(newCtx->fileInfo), sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);

	
	return retVal;
}






FLT_PREOP_CALLBACK_STATUS
PreRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}




FLT_POSTOP_CALLBACK_STATUS
PostRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	FLT_POSTOP_CALLBACK_STATUS retVal = FLT_POSTOP_FINISHED_PROCESSING;

	//get the data then print it
	PVOID buffer = NULL;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PSTREAM_HANDLE_CONTEXT context = NULL;
	NTSTATUS status;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return retVal;
	}

	//check the context
	status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&context);
	if (!NT_SUCCESS(status))
	{
		return retVal;
	}
	if (context == NULL)
	{
		return retVal;
	}
	if (!(context->isEncryptFileType))
	{
		return retVal;
	}
	DbgPrint("The File is a encrypt file type");
	
	PCHAR procName = GetCurrentProcessName();
	DbgPrint("the Process Name in Post Read : %s", procName);
	if (!IsSecretProcess(context->ftp, procName))
	{
		return retVal;
	}



	if (iopb->Parameters.Read.MdlAddress != NULL)
	{
		buffer = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority);
	}

	if (buffer == NULL)
	{
		buffer = iopb->Parameters.Read.ReadBuffer;
	}
	if (buffer == NULL)
	{
		DbgPrint("Can't get buffer in Post Read");
		return retVal;
	}

	DbgPrint("%s", buffer);

	

	return retVal;
}



/*++
	Additional function
--*/
ULONG GetProcessNameOffset()
{
	ULONG i;

	PEPROCESS curproc = PsGetCurrentProcess();
	for (i = 0; i < 3 * PAGE_SIZE; i++)
	{
		if (!strncmp("System", (PCHAR)curproc + i, strlen("System")))
		{
			return i;
		}
	}
	return 0;
}

PCHAR GetCurrentProcessName()
{
	PCHAR name = NULL;
	PEPROCESS curproc = PsGetCurrentProcess();

	if (offset)
	{
		name = (PCHAR)curproc + offset;
	}
	return name;
}

