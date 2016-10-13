#include "Context.h"





VOID CleanupStreamHandleContext(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType)
{
	UNREFERENCED_PARAMETER(ContextType);

	FltReleaseContext(Context);
}

NTSTATUS 
GetFileEncryptInfoToContext(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
	PSTREAM_HANDLE_CONTEXT Context, PFILE_TYPE_PROCESS head)
{
	NTSTATUS status;
	Context->isEncrypted = FALSE;
	Context->isEncryptFileType = FALSE;
	Context->ftp = NULL;

	//get the file information
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	BOOLEAN isDir;
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);

	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (isDir)
	{
		DbgPrint("It's a Directory\n");
		return status;
	}


	//get file name
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	FltParseFileNameInformation(&nameInfo);
	DbgPrint("   Current file name is %wZ", &(nameInfo->Name));

	BOOLEAN isEncryptFileType = IsInStrategyList(head, &(nameInfo->Name), &(Context->ftp));

	if (!isEncryptFileType)
	{
		DbgPrint("It's not the encrypt file type\n");
	}
	else
	{
		DbgPrint("    Current file is a encrypt file type");

		//then check the  file has been encrypted or not
		Context->isEncryptFileType = TRUE;
	}


	if (nameInfo != NULL)
	{
		FltReleaseFileNameInformation(nameInfo);
	}

	return status;
}
