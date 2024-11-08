































typedef struct _SERIAL_DEVICE SERIAL_DEVICE;

struct _SERIAL_DEVICE {
	DEVICE device;
	BOOL permissive;
	SERIAL_DRIVER_ID ServerSerialDriverId;
	HANDLE* hComm;

	wLog* log;
	HANDLE MainThread;
	wMessageQueue* MainIrpQueue;

	
	wListDictionary* IrpThreads;
	UINT32 IrpThreadToBeTerminatedCount;
	CRITICAL_SECTION TerminatingIrpThreadsLock;
	rdpContext* rdpcontext;
};

typedef struct _IRP_THREAD_DATA IRP_THREAD_DATA;

struct _IRP_THREAD_DATA {
	SERIAL_DEVICE* serial;
	IRP* irp;
};

static UINT32 _GetLastErrorToIoStatus(SERIAL_DEVICE* serial)
{
	
	switch (GetLastError())
	{
		case ERROR_BAD_DEVICE:
			return STATUS_INVALID_DEVICE_REQUEST;

		case ERROR_CALL_NOT_IMPLEMENTED:
			return STATUS_NOT_IMPLEMENTED;

		case ERROR_CANCELLED:
			return STATUS_CANCELLED;

		case ERROR_INSUFFICIENT_BUFFER:
			return STATUS_BUFFER_TOO_SMALL; 

		case ERROR_INVALID_DEVICE_OBJECT_PARAMETER: 
			return STATUS_INVALID_DEVICE_STATE;

		case ERROR_INVALID_HANDLE:
			return STATUS_INVALID_DEVICE_REQUEST;

		case ERROR_INVALID_PARAMETER:
			return STATUS_INVALID_PARAMETER;

		case ERROR_IO_DEVICE:
			return STATUS_IO_DEVICE_ERROR;

		case ERROR_IO_PENDING:
			return STATUS_PENDING;

		case ERROR_NOT_SUPPORTED:
			return STATUS_NOT_SUPPORTED;

		case ERROR_TIMEOUT:
			return STATUS_TIMEOUT;
			
	}

	WLog_Print(serial->log, WLOG_DEBUG, "unexpected last-error: 0x%08" PRIX32 "", GetLastError());
	return STATUS_UNSUCCESSFUL;
}

static UINT serial_process_irp_create(SERIAL_DEVICE* serial, IRP* irp)
{
	DWORD DesiredAccess;
	DWORD SharedAccess;
	DWORD CreateDisposition;
	UINT32 PathLength;

	if (Stream_GetRemainingLength(irp->input) < 32)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(irp->input, DesiredAccess);     
	Stream_Seek_UINT64(irp->input);                    
	Stream_Seek_UINT32(irp->input);                    
	Stream_Read_UINT32(irp->input, SharedAccess);      
	Stream_Read_UINT32(irp->input, CreateDisposition); 
	Stream_Seek_UINT32(irp->input);                    
	Stream_Read_UINT32(irp->input, PathLength);        

	if (Stream_GetRemainingLength(irp->input) < PathLength)
		return ERROR_INVALID_DATA;

	Stream_Seek(irp->input, PathLength); 
	assert(PathLength == 0);             

	
	WLog_Print(serial->log, WLOG_DEBUG, "DesiredAccess: 0x%" PRIX32 ", SharedAccess: 0x%" PRIX32 ", CreateDisposition: 0x%" PRIX32 "", DesiredAccess, SharedAccess, CreateDisposition);


	
	DesiredAccess = GENERIC_READ | GENERIC_WRITE;
	SharedAccess = 0;
	CreateDisposition = OPEN_EXISTING;

	serial->hComm = CreateFile(serial->device.name, DesiredAccess, SharedAccess, NULL, CreateDisposition, 0, NULL);



	if (!serial->hComm || (serial->hComm == INVALID_HANDLE_VALUE))
	{
		WLog_Print(serial->log, WLOG_WARN, "CreateFile failure: %s last-error: 0x%08" PRIX32 "", serial->device.name, GetLastError());
		irp->IoStatus = STATUS_UNSUCCESSFUL;
		goto error_handle;
	}

	_comm_setServerSerialDriver(serial->hComm, serial->ServerSerialDriverId);
	_comm_set_permissive(serial->hComm, serial->permissive);
	
	
	
	
	
	
	assert(irp->FileId == 0);
	irp->FileId = irp->devman->id_sequence++; 
	irp->IoStatus = STATUS_SUCCESS;
	WLog_Print(serial->log, WLOG_DEBUG, "%s (DeviceId: %" PRIu32 ", FileId: %" PRIu32 ") created.", serial->device.name, irp->device->id, irp->FileId);
error_handle:
	Stream_Write_UINT32(irp->output, irp->FileId); 
	Stream_Write_UINT8(irp->output, 0);            
	return CHANNEL_RC_OK;
}

static UINT serial_process_irp_close(SERIAL_DEVICE* serial, IRP* irp)
{
	if (Stream_GetRemainingLength(irp->input) < 32)
		return ERROR_INVALID_DATA;

	Stream_Seek(irp->input, 32); 

	if (!CloseHandle(serial->hComm))
	{
		WLog_Print(serial->log, WLOG_WARN, "CloseHandle failure: %s (%" PRIu32 ") closed.", serial->device.name, irp->device->id);
		irp->IoStatus = STATUS_UNSUCCESSFUL;
		goto error_handle;
	}

	WLog_Print(serial->log, WLOG_DEBUG, "%s (DeviceId: %" PRIu32 ", FileId: %" PRIu32 ") closed.", serial->device.name, irp->device->id, irp->FileId);
	serial->hComm = NULL;
	irp->IoStatus = STATUS_SUCCESS;
error_handle:
	Stream_Zero(irp->output, 5); 
	return CHANNEL_RC_OK;
}


static UINT serial_process_irp_read(SERIAL_DEVICE* serial, IRP* irp)
{
	UINT32 Length;
	UINT64 Offset;
	BYTE* buffer = NULL;
	DWORD nbRead = 0;

	if (Stream_GetRemainingLength(irp->input) < 32)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(irp->input, Length); 
	Stream_Read_UINT64(irp->input, Offset); 
	Stream_Seek(irp->input, 20);            
	buffer = (BYTE*)calloc(Length, sizeof(BYTE));

	if (buffer == NULL)
	{
		irp->IoStatus = STATUS_NO_MEMORY;
		goto error_handle;
	}

	
	WLog_Print(serial->log, WLOG_DEBUG, "reading %" PRIu32 " bytes from %s", Length, serial->device.name);

	
	if (CommReadFile(serial->hComm, buffer, Length, &nbRead, NULL))
	{
		irp->IoStatus = STATUS_SUCCESS;
	}
	else {
		WLog_Print(serial->log, WLOG_DEBUG, "read failure to %s, nbRead=%" PRIu32 ", last-error: 0x%08" PRIX32 "", serial->device.name, nbRead, GetLastError());

		irp->IoStatus = _GetLastErrorToIoStatus(serial);
	}

	WLog_Print(serial->log, WLOG_DEBUG, "%" PRIu32 " bytes read from %s", nbRead, serial->device.name);
error_handle:
	Stream_Write_UINT32(irp->output, nbRead); 

	if (nbRead > 0)
	{
		if (!Stream_EnsureRemainingCapacity(irp->output, nbRead))
		{
			WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed!");
			free(buffer);
			return CHANNEL_RC_NO_MEMORY;
		}

		Stream_Write(irp->output, buffer, nbRead); 
	}

	free(buffer);
	return CHANNEL_RC_OK;
}

static UINT serial_process_irp_write(SERIAL_DEVICE* serial, IRP* irp)
{
	UINT32 Length;
	UINT64 Offset;
	DWORD nbWritten = 0;

	if (Stream_GetRemainingLength(irp->input) < 32)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(irp->input, Length); 
	Stream_Read_UINT64(irp->input, Offset); 
	Stream_Seek(irp->input, 20);            
	
	WLog_Print(serial->log, WLOG_DEBUG, "writing %" PRIu32 " bytes to %s", Length, serial->device.name);

	
	if (CommWriteFile(serial->hComm, Stream_Pointer(irp->input), Length, &nbWritten, NULL))
	{
		irp->IoStatus = STATUS_SUCCESS;
	}
	else {
		WLog_Print(serial->log, WLOG_DEBUG, "write failure to %s, nbWritten=%" PRIu32 ", last-error: 0x%08" PRIX32 "", serial->device.name, nbWritten, GetLastError());

		irp->IoStatus = _GetLastErrorToIoStatus(serial);
	}

	WLog_Print(serial->log, WLOG_DEBUG, "%" PRIu32 " bytes written to %s", nbWritten, serial->device.name);
	Stream_Write_UINT32(irp->output, nbWritten); 
	Stream_Write_UINT8(irp->output, 0);          
	return CHANNEL_RC_OK;
}


static UINT serial_process_irp_device_control(SERIAL_DEVICE* serial, IRP* irp)
{
	UINT32 IoControlCode;
	UINT32 InputBufferLength;
	BYTE* InputBuffer = NULL;
	UINT32 OutputBufferLength;
	BYTE* OutputBuffer = NULL;
	DWORD BytesReturned = 0;

	if (Stream_GetRemainingLength(irp->input) < 32)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(irp->input, OutputBufferLength); 
	Stream_Read_UINT32(irp->input, InputBufferLength);  
	Stream_Read_UINT32(irp->input, IoControlCode);      
	Stream_Seek(irp->input, 20);                        

	if (Stream_GetRemainingLength(irp->input) < InputBufferLength)
		return ERROR_INVALID_DATA;

	OutputBuffer = (BYTE*)calloc(OutputBufferLength, sizeof(BYTE));

	if (OutputBuffer == NULL)
	{
		irp->IoStatus = STATUS_NO_MEMORY;
		goto error_handle;
	}

	InputBuffer = (BYTE*)calloc(InputBufferLength, sizeof(BYTE));

	if (InputBuffer == NULL)
	{
		irp->IoStatus = STATUS_NO_MEMORY;
		goto error_handle;
	}

	Stream_Read(irp->input, InputBuffer, InputBufferLength);
	WLog_Print(serial->log, WLOG_DEBUG, "CommDeviceIoControl: CompletionId=%" PRIu32 ", IoControlCode=[0x%" PRIX32 "] %s", irp->CompletionId, IoControlCode, _comm_serial_ioctl_name(IoControlCode));


	
	if (CommDeviceIoControl(serial->hComm, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &BytesReturned, NULL))
	{
		
		irp->IoStatus = STATUS_SUCCESS;
	}
	else {
		WLog_Print(serial->log, WLOG_DEBUG, "CommDeviceIoControl failure: IoControlCode=[0x%" PRIX32 "] %s, last-error: 0x%08" PRIX32 "", IoControlCode, _comm_serial_ioctl_name(IoControlCode), GetLastError());


		irp->IoStatus = _GetLastErrorToIoStatus(serial);
	}

error_handle:
	
	assert(OutputBufferLength == BytesReturned);
	Stream_Write_UINT32(irp->output, BytesReturned); 

	if (BytesReturned > 0)
	{
		if (!Stream_EnsureRemainingCapacity(irp->output, BytesReturned))
		{
			WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed!");
			free(InputBuffer);
			free(OutputBuffer);
			return CHANNEL_RC_NO_MEMORY;
		}

		Stream_Write(irp->output, OutputBuffer, BytesReturned); 
	}

	
	
	
	
	
	free(InputBuffer);
	free(OutputBuffer);
	return CHANNEL_RC_OK;
}


static UINT serial_process_irp(SERIAL_DEVICE* serial, IRP* irp)
{
	UINT error = CHANNEL_RC_OK;
	WLog_Print(serial->log, WLOG_DEBUG, "IRP MajorFunction: 0x%08" PRIX32 " MinorFunction: 0x%08" PRIX32 "\n", irp->MajorFunction, irp->MinorFunction);


	switch (irp->MajorFunction)
	{
		case IRP_MJ_CREATE:
			error = serial_process_irp_create(serial, irp);
			break;

		case IRP_MJ_CLOSE:
			error = serial_process_irp_close(serial, irp);
			break;

		case IRP_MJ_READ:
			if ((error = serial_process_irp_read(serial, irp)))
				WLog_ERR(TAG, "serial_process_irp_read failed with error %" PRIu32 "!", error);

			break;

		case IRP_MJ_WRITE:
			error = serial_process_irp_write(serial, irp);
			break;

		case IRP_MJ_DEVICE_CONTROL:
			if ((error = serial_process_irp_device_control(serial, irp)))
				WLog_ERR(TAG, "serial_process_irp_device_control failed with error %" PRIu32 "!", error);

			break;

		default:
			irp->IoStatus = STATUS_NOT_SUPPORTED;
			break;
	}

	return error;
}

static DWORD WINAPI irp_thread_func(LPVOID arg)
{
	IRP_THREAD_DATA* data = (IRP_THREAD_DATA*)arg;
	UINT error;

	
	if ((error = serial_process_irp(data->serial, data->irp)))
	{
		WLog_ERR(TAG, "serial_process_irp failed with error %" PRIu32 "", error);
		goto error_out;
	}

	EnterCriticalSection(&data->serial->TerminatingIrpThreadsLock);
	data->serial->IrpThreadToBeTerminatedCount++;
	error = data->irp->Complete(data->irp);
	LeaveCriticalSection(&data->serial->TerminatingIrpThreadsLock);
error_out:

	if (error && data->serial->rdpcontext)
		setChannelError(data->serial->rdpcontext, error, "irp_thread_func reported an error");

	
	free(data);
	ExitThread(error);
	return error;
}

static void create_irp_thread(SERIAL_DEVICE* serial, IRP* irp)
{
	IRP_THREAD_DATA* data = NULL;
	HANDLE irpThread;
	HANDLE previousIrpThread;
	uintptr_t key;
	
	
	
	
	
	EnterCriticalSection(&serial->TerminatingIrpThreadsLock);

	while (serial->IrpThreadToBeTerminatedCount > 0)
	{
		
		HANDLE irpThread;
		ULONG_PTR* ids;
		int i, nbIds;
		nbIds = ListDictionary_GetKeys(serial->IrpThreads, &ids);

		for (i = 0; i < nbIds; i++)
		{
			
			DWORD waitResult;
			ULONG_PTR id = ids[i];
			irpThread = ListDictionary_GetItemValue(serial->IrpThreads, (void*)id);
			
			waitResult = WaitForSingleObject(irpThread, 0);

			if (waitResult == WAIT_OBJECT_0)
			{
				
				
				CloseHandle(irpThread);
				ListDictionary_Remove(serial->IrpThreads, (void*)id);
				serial->IrpThreadToBeTerminatedCount--;
			}
			else if (waitResult != WAIT_TIMEOUT)
			{
				
				WLog_Print(serial->log, WLOG_WARN, "WaitForSingleObject, got an unexpected result=0x%" PRIX32 "\n", waitResult);

				assert(FALSE);
			}

			
		}

		if (serial->IrpThreadToBeTerminatedCount > 0)
		{
			WLog_Print(serial->log, WLOG_DEBUG, "%" PRIu32 " IRP thread(s) not yet terminated", serial->IrpThreadToBeTerminatedCount);
			Sleep(1); 
		}

		free(ids);
	}

	LeaveCriticalSection(&serial->TerminatingIrpThreadsLock);
	
	key = irp->CompletionId;
	previousIrpThread = ListDictionary_GetItemValue(serial->IrpThreads, (void*)key);

	if (previousIrpThread)
	{
		
		WLog_Print(serial->log, WLOG_DEBUG, "IRP recall: IRP with the CompletionId=%" PRIu32 " not yet completed!", irp->CompletionId);

		assert(FALSE); 
		
		
		irp->Discard(irp);
		return;
	}

	if (ListDictionary_Count(serial->IrpThreads) >= MAX_IRP_THREADS)
	{
		WLog_Print(serial->log, WLOG_WARN, "Number of IRP threads threshold reached: %d, keep on anyway", ListDictionary_Count(serial->IrpThreads));

		assert(FALSE); 
		               
	}

	
	data = (IRP_THREAD_DATA*)calloc(1, sizeof(IRP_THREAD_DATA));

	if (data == NULL)
	{
		WLog_Print(serial->log, WLOG_WARN, "Could not allocate a new IRP_THREAD_DATA.");
		goto error_handle;
	}

	data->serial = serial;
	data->irp = irp;
	
	irpThread = CreateThread(NULL, 0, irp_thread_func, (void*)data, 0, NULL);

	if (irpThread == INVALID_HANDLE_VALUE)
	{
		WLog_Print(serial->log, WLOG_WARN, "Could not allocate a new IRP thread.");
		goto error_handle;
	}

	key = irp->CompletionId;

	if (!ListDictionary_Add(serial->IrpThreads, (void*)key, irpThread))
	{
		WLog_ERR(TAG, "ListDictionary_Add failed!");
		goto error_handle;
	}

	return;
error_handle:
	irp->IoStatus = STATUS_NO_MEMORY;
	irp->Complete(irp);
	free(data);
}

static void terminate_pending_irp_threads(SERIAL_DEVICE* serial)
{
	ULONG_PTR* ids;
	int i, nbIds;
	nbIds = ListDictionary_GetKeys(serial->IrpThreads, &ids);
	WLog_Print(serial->log, WLOG_DEBUG, "Terminating %d IRP thread(s)", nbIds);

	for (i = 0; i < nbIds; i++)
	{
		HANDLE irpThread;
		ULONG_PTR id = ids[i];
		irpThread = ListDictionary_GetItemValue(serial->IrpThreads, (void*)id);
		TerminateThread(irpThread, 0);

		if (WaitForSingleObject(irpThread, INFINITE) == WAIT_FAILED)
		{
			WLog_ERR(TAG, "WaitForSingleObject failed!");
			continue;
		}

		CloseHandle(irpThread);
		WLog_Print(serial->log, WLOG_DEBUG, "IRP thread terminated, CompletionId %p", (void*)id);
	}

	ListDictionary_Clear(serial->IrpThreads);
	free(ids);
}

static DWORD WINAPI serial_thread_func(LPVOID arg)
{
	IRP* irp;
	wMessage message;
	SERIAL_DEVICE* serial = (SERIAL_DEVICE*)arg;
	UINT error = CHANNEL_RC_OK;

	while (1)
	{
		if (!MessageQueue_Wait(serial->MainIrpQueue))
		{
			WLog_ERR(TAG, "MessageQueue_Wait failed!");
			error = ERROR_INTERNAL_ERROR;
			break;
		}

		if (!MessageQueue_Peek(serial->MainIrpQueue, &message, TRUE))
		{
			WLog_ERR(TAG, "MessageQueue_Peek failed!");
			error = ERROR_INTERNAL_ERROR;
			break;
		}

		if (message.id == WMQ_QUIT)
		{
			terminate_pending_irp_threads(serial);
			break;
		}

		irp = (IRP*)message.wParam;

		if (irp)
			create_irp_thread(serial, irp);
	}

	if (error && serial->rdpcontext)
		setChannelError(serial->rdpcontext, error, "serial_thread_func reported an error");

	ExitThread(error);
	return error;
}


static UINT serial_irp_request(DEVICE* device, IRP* irp)
{
	SERIAL_DEVICE* serial = (SERIAL_DEVICE*)device;
	assert(irp != NULL);

	if (irp == NULL)
		return CHANNEL_RC_OK;

	

	if (!MessageQueue_Post(serial->MainIrpQueue, NULL, 0, (void*)irp, NULL))
	{
		WLog_ERR(TAG, "MessageQueue_Post failed!");
		return ERROR_INTERNAL_ERROR;
	}

	return CHANNEL_RC_OK;
}


static UINT serial_free(DEVICE* device)
{
	UINT error;
	SERIAL_DEVICE* serial = (SERIAL_DEVICE*)device;
	WLog_Print(serial->log, WLOG_DEBUG, "freeing");
	MessageQueue_PostQuit(serial->MainIrpQueue, 0);

	if (WaitForSingleObject(serial->MainThread, INFINITE) == WAIT_FAILED)
	{
		error = GetLastError();
		WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "!", error);
		return error;
	}

	CloseHandle(serial->MainThread);

	if (serial->hComm)
		CloseHandle(serial->hComm);

	
	Stream_Free(serial->device.data, TRUE);
	MessageQueue_Free(serial->MainIrpQueue);
	ListDictionary_Free(serial->IrpThreads);
	DeleteCriticalSection(&serial->TerminatingIrpThreadsLock);
	free(serial);
	return CHANNEL_RC_OK;
}










UINT DeviceServiceEntry(PDEVICE_SERVICE_ENTRY_POINTS pEntryPoints)
{
	char* name;
	char* path;
	char* driver;
	RDPDR_SERIAL* device;

	size_t i, len;
	SERIAL_DEVICE* serial;

	UINT error = CHANNEL_RC_OK;
	device = (RDPDR_SERIAL*)pEntryPoints->device;
	name = device->Name;
	path = device->Path;
	driver = device->Driver;

	if (!name || (name[0] == '*'))
	{
		
		return CHANNEL_RC_OK;
	}

	if ((name && name[0]) && (path && path[0]))
	{
		wLog* log;
		log = WLog_Get("com.freerdp.channel.serial.client");
		WLog_Print(log, WLOG_DEBUG, "initializing");

		WLog_Print(log, WLOG_WARN, "Serial ports redirection not supported on this platform.");
		return CHANNEL_RC_INITIALIZATION_ERROR;

		WLog_Print(log, WLOG_DEBUG, "Defining %s as %s", name, path);

		if (!DefineCommDevice(name , path ))
		{
			DWORD status = GetLastError();
			WLog_ERR(TAG, "DefineCommDevice failed with %08" PRIx32, status);
			return ERROR_INTERNAL_ERROR;
		}

		serial = (SERIAL_DEVICE*)calloc(1, sizeof(SERIAL_DEVICE));

		if (!serial)
		{
			WLog_ERR(TAG, "calloc failed!");
			return CHANNEL_RC_NO_MEMORY;
		}

		serial->log = log;
		serial->device.type = RDPDR_DTYP_SERIAL;
		serial->device.name = name;
		serial->device.IRPRequest = serial_irp_request;
		serial->device.Free = serial_free;
		serial->rdpcontext = pEntryPoints->rdpcontext;
		len = strlen(name);
		serial->device.data = Stream_New(NULL, len + 1);

		if (!serial->device.data)
		{
			WLog_ERR(TAG, "calloc failed!");
			error = CHANNEL_RC_NO_MEMORY;
			goto error_out;
		}

		for (i = 0; i <= len; i++)
			Stream_Write_UINT8(serial->device.data, name[i] < 0 ? '_' : name[i]);

		if (driver != NULL)
		{
			if (_stricmp(driver, "Serial") == 0)
				serial->ServerSerialDriverId = SerialDriverSerialSys;
			else if (_stricmp(driver, "SerCx") == 0)
				serial->ServerSerialDriverId = SerialDriverSerCxSys;
			else if (_stricmp(driver, "SerCx2") == 0)
				serial->ServerSerialDriverId = SerialDriverSerCx2Sys;
			else {
				assert(FALSE);
				WLog_Print(serial->log, WLOG_DEBUG, "Unknown server's serial driver: %s. SerCx2 will be used", driver);
				serial->ServerSerialDriverId = SerialDriverSerialSys;
			}
		}
		else {
			
			serial->ServerSerialDriverId = SerialDriverSerialSys;
		}

		if (device->Permissive != NULL)
		{
			if (_stricmp(device->Permissive, "permissive") == 0)
			{
				serial->permissive = TRUE;
			}
			else {
				WLog_Print(serial->log, WLOG_DEBUG, "Unknown flag: %s", device->Permissive);
				assert(FALSE);
			}
		}

		WLog_Print(serial->log, WLOG_DEBUG, "Server's serial driver: %s (id: %d)", driver, serial->ServerSerialDriverId);
		
		serial->MainIrpQueue = MessageQueue_New(NULL);

		if (!serial->MainIrpQueue)
		{
			WLog_ERR(TAG, "MessageQueue_New failed!");
			error = CHANNEL_RC_NO_MEMORY;
			goto error_out;
		}

		
		serial->IrpThreads = ListDictionary_New(FALSE);

		if (!serial->IrpThreads)
		{
			WLog_ERR(TAG, "ListDictionary_New failed!");
			error = CHANNEL_RC_NO_MEMORY;
			goto error_out;
		}

		serial->IrpThreadToBeTerminatedCount = 0;
		InitializeCriticalSection(&serial->TerminatingIrpThreadsLock);

		if ((error = pEntryPoints->RegisterDevice(pEntryPoints->devman, (DEVICE*)serial)))
		{
			WLog_ERR(TAG, "EntryPoints->RegisterDevice failed with error %" PRIu32 "!", error);
			goto error_out;
		}

		if (!(serial->MainThread = CreateThread(NULL, 0, serial_thread_func, (void*)serial, 0, NULL)))
		{
			WLog_ERR(TAG, "CreateThread failed!");
			error = ERROR_INTERNAL_ERROR;
			goto error_out;
		}


	}

	return error;
error_out:

	ListDictionary_Free(serial->IrpThreads);
	MessageQueue_Free(serial->MainIrpQueue);
	Stream_Free(serial->device.data, TRUE);
	free(serial);

	return error;
}
