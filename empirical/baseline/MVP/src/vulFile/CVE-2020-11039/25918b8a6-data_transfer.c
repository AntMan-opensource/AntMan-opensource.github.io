












static void usb_process_get_port_status(IUDEVICE* pdev, wStream* out)
{
	int bcdUSB = pdev->query_device_descriptor(pdev, BCD_USB);

	switch (bcdUSB)
	{
		case USB_v1_0:
			Stream_Write_UINT32(out, 0x303);
			break;

		case USB_v1_1:
			Stream_Write_UINT32(out, 0x103);
			break;

		case USB_v2_0:
			Stream_Write_UINT32(out, 0x503);
			break;

		default:
			Stream_Write_UINT32(out, 0x503);
			break;
	}
}

static UINT urb_write_completion(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, BOOL noAck, wStream* out, UINT32 InterfaceId, UINT32 MessageId, UINT32 RequestId, UINT32 usbd_status, UINT32 OutputBufferSize)

{
	if (!out)
		return ERROR_INVALID_PARAMETER;

	if (Stream_Capacity(out) < OutputBufferSize + 36)
	{
		Stream_Free(out, TRUE);
		return ERROR_INVALID_PARAMETER;
	}

	Stream_SetPosition(out, 0);
	Stream_Write_UINT32(out, InterfaceId); 
	Stream_Write_UINT32(out, MessageId);   

	if (OutputBufferSize != 0)
		Stream_Write_UINT32(out, URB_COMPLETION);
	else Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA);

	Stream_Write_UINT32(out, RequestId); 
	Stream_Write_UINT32(out, 8);         
	
	Stream_Write_UINT16(out, 8);                
	Stream_Write_UINT16(out, 0);                
	Stream_Write_UINT32(out, usbd_status);      
	Stream_Write_UINT32(out, 0);                
	Stream_Write_UINT32(out, OutputBufferSize); 
	Stream_Seek(out, OutputBufferSize);

	if (!noAck)
		return stream_write_and_free(callback->plugin, callback->channel, out);
	else Stream_Free(out, TRUE);

	return ERROR_SUCCESS;
}

static wStream* urb_create_iocompletion(UINT32 InterfaceField, UINT32 MessageId, UINT32 RequestId, UINT32 OutputBufferSize)
{
	const UINT32 InterfaceId = (STREAM_ID_PROXY << 30) | (InterfaceField & 0x3FFFFFFF);
	wStream* out = Stream_New(NULL, OutputBufferSize + 28);

	if (!out)
		return NULL;

	Stream_Write_UINT32(out, InterfaceId);          
	Stream_Write_UINT32(out, MessageId);            
	Stream_Write_UINT32(out, IOCONTROL_COMPLETION); 
	Stream_Write_UINT32(out, RequestId);            
	Stream_Write_UINT32(out, USBD_STATUS_SUCCESS);  
	Stream_Write_UINT32(out, OutputBufferSize);     
	Stream_Write_UINT32(out, OutputBufferSize);     
	return out;
}

static UINT urbdrc_process_register_request_callback(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, IUDEVMAN* udevman)

{
	UINT32 NumRequestCompletion = 0;
	UINT32 RequestCompletion = 0;
	URBDRC_PLUGIN* urbdrc;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	WLog_Print(urbdrc->log, WLOG_DEBUG, "urbdrc_process_register_request_callback");

	if (Stream_GetRemainingLength(s) >= 8)
	{
		Stream_Read_UINT32(s, NumRequestCompletion); 
		
		Stream_Read_UINT32(s, RequestCompletion);
		pdev->set_ReqCompletion(pdev, RequestCompletion);
	}
	else if (Stream_GetRemainingLength(s) >= 4) 
	{
		Stream_Read_UINT32(s, RequestCompletion);

		if (pdev->get_ReqCompletion(pdev) == RequestCompletion)
			pdev->setChannelClosed(pdev);
	}
	else return ERROR_INVALID_DATA;

	return ERROR_SUCCESS;
}

static UINT urbdrc_process_cancel_request(IUDEVICE* pdev, wStream* s, IUDEVMAN* udevman)
{
	UINT32 CancelId;
	URBDRC_PLUGIN* urbdrc;

	if (!s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)udevman->plugin;

	if (Stream_GetRemainingLength(s) < 4)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, CancelId);
	WLog_Print(urbdrc->log, WLOG_DEBUG, "CANCEL_REQUEST: CancelId=%08" PRIx32 "", CancelId);

	if (pdev->cancel_transfer_request(pdev, CancelId) < 0)
		return ERROR_INTERNAL_ERROR;

	return ERROR_SUCCESS;
}

static UINT urbdrc_process_retract_device_request(IUDEVICE* pdev, wStream* s, IUDEVMAN* udevman)
{
	UINT32 Reason;
	URBDRC_PLUGIN* urbdrc;

	if (!s || !udevman)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)udevman->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 4)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, Reason); 

	switch (Reason)
	{
		case UsbRetractReason_BlockedByPolicy:
			WLog_Print(urbdrc->log, WLOG_DEBUG, "UsbRetractReason_BlockedByPolicy: now it is not support");
			return ERROR_ACCESS_DENIED;

		default:
			WLog_Print(urbdrc->log, WLOG_DEBUG, "urbdrc_process_retract_device_request: Unknown Reason %" PRIu32 "", Reason);
			return ERROR_ACCESS_DENIED;
	}

	return ERROR_SUCCESS;
}

static UINT urbdrc_process_io_control(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 MessageId, IUDEVMAN* udevman)
{
	UINT32 InterfaceId;
	UINT32 IoControlCode;
	UINT32 InputBufferSize;
	UINT32 OutputBufferSize;
	UINT32 RequestId;
	UINT32 usbd_status = USBD_STATUS_SUCCESS;
	wStream* out;
	int success = 0;
	URBDRC_PLUGIN* urbdrc;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, IoControlCode);
	Stream_Read_UINT32(s, InputBufferSize);

	if (Stream_GetRemainingLength(s) < InputBufferSize + 8)
		return ERROR_INVALID_DATA;

	Stream_Seek(s, InputBufferSize);
	Stream_Read_UINT32(s, OutputBufferSize);
	Stream_Read_UINT32(s, RequestId);
	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out = urb_create_iocompletion(InterfaceId, MessageId, RequestId, OutputBufferSize);

	if (!out)
		return ERROR_OUTOFMEMORY;

	switch (IoControlCode)
	{
		case IOCTL_INTERNAL_USB_SUBMIT_URB: 
			WLog_Print(urbdrc->log, WLOG_DEBUG, "ioctl: IOCTL_INTERNAL_USB_SUBMIT_URB");
			WLog_Print(urbdrc->log, WLOG_ERROR, " Function IOCTL_INTERNAL_USB_SUBMIT_URB: Unchecked");
			break;

		case IOCTL_INTERNAL_USB_RESET_PORT: 
			WLog_Print(urbdrc->log, WLOG_DEBUG, "ioctl: IOCTL_INTERNAL_USB_RESET_PORT");
			break;

		case IOCTL_INTERNAL_USB_GET_PORT_STATUS: 
			WLog_Print(urbdrc->log, WLOG_DEBUG, "ioctl: IOCTL_INTERNAL_USB_GET_PORT_STATUS");
			success = pdev->query_device_port_status(pdev, &usbd_status, &OutputBufferSize, Stream_Pointer(out));

			if (success)
			{
				Stream_Seek(out, OutputBufferSize);

				if (pdev->isExist(pdev) == 0)
					Stream_Write_UINT32(out, 0);
				else usb_process_get_port_status(pdev, out);
			}

			break;

		case IOCTL_INTERNAL_USB_CYCLE_PORT: 
			WLog_Print(urbdrc->log, WLOG_DEBUG, "ioctl: IOCTL_INTERNAL_USB_CYCLE_PORT");
			WLog_Print(urbdrc->log, WLOG_ERROR, " Function IOCTL_INTERNAL_USB_CYCLE_PORT: Unchecked");
			break;

		case IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION: 
			WLog_Print(urbdrc->log, WLOG_DEBUG, "ioctl: IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION");
			WLog_Print(urbdrc->log, WLOG_ERROR, " Function IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION: Unchecked");
			break;

		default:
			WLog_Print(urbdrc->log, WLOG_DEBUG, "urbdrc_process_io_control: unknown IoControlCode 0x%" PRIX32 "", IoControlCode);

			Stream_Free(out, TRUE);
			return ERROR_INVALID_OPERATION;
	}

	return stream_write_and_free(callback->plugin, callback->channel, out);
}

static UINT urbdrc_process_internal_io_control(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 MessageId, IUDEVMAN* udevman)
{
	wStream* out;
	UINT32 IoControlCode, InterfaceId, InputBufferSize;
	UINT32 OutputBufferSize, RequestId, frames;

	if (!pdev || !callback || !s || !udevman)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, IoControlCode);
	Stream_Read_UINT32(s, InputBufferSize);

	if (Stream_GetRemainingLength(s) < InputBufferSize + 8)
		return ERROR_INVALID_DATA;

	Stream_Seek(s, InputBufferSize);
	Stream_Read_UINT32(s, OutputBufferSize);
	Stream_Read_UINT32(s, RequestId);
	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	
	
	frames = GetTickCount();
	out = urb_create_iocompletion(InterfaceId, MessageId, RequestId, 4);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Write_UINT32(out, frames); 
	return stream_write_and_free(callback->plugin, callback->channel, out);
}

static UINT urbdrc_process_query_device_text(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 MessageId, IUDEVMAN* udevman)
{
	UINT32 out_size;
	UINT32 TextType;
	UINT32 LocaleId;
	UINT32 InterfaceId;
	UINT8 bufferSize = 0xFF;
	UINT32 hr;
	wStream* out;
	BYTE DeviceDescription[0x100] = { 0 };

	if (!pdev || !callback || !s || !udevman)
		return ERROR_INVALID_PARAMETER;
	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, TextType);
	Stream_Read_UINT32(s, LocaleId);
	if (LocaleId > UINT16_MAX)
		return ERROR_INVALID_DATA;

	hr = pdev->control_query_device_text(pdev, TextType, (UINT16)LocaleId, &bufferSize, DeviceDescription);
	InterfaceId = ((STREAM_ID_STUB << 30) | pdev->get_UsbDevice(pdev));
	out_size = 16 + bufferSize;

	if (bufferSize != 0)
		out_size += 2;

	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Write_UINT32(out, InterfaceId);            
	Stream_Write_UINT32(out, MessageId);              
	Stream_Write_UINT32(out, bufferSize / 2);         
	Stream_Write(out, DeviceDescription, bufferSize); 
	Stream_Write_UINT32(out, hr);                     
	return stream_write_and_free(callback->plugin, callback->channel, out);
}

static void func_select_all_interface_for_msconfig(IUDEVICE* pdev, MSUSB_CONFIG_DESCRIPTOR* MsConfig)
{
	UINT32 inum;
	MSUSB_INTERFACE_DESCRIPTOR** MsInterfaces = MsConfig->MsInterfaces;
	BYTE InterfaceNumber, AlternateSetting;
	UINT32 NumInterfaces = MsConfig->NumInterfaces;

	for (inum = 0; inum < NumInterfaces; inum++)
	{
		InterfaceNumber = MsInterfaces[inum]->InterfaceNumber;
		AlternateSetting = MsInterfaces[inum]->AlternateSetting;
		pdev->select_interface(pdev, InterfaceNumber, AlternateSetting);
	}
}

static UINT urb_select_configuration(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	MSUSB_CONFIG_DESCRIPTOR* MsConfig = NULL;
	UINT32 out_size, InterfaceId, NumInterfaces, usbd_status = 0;
	BYTE ConfigurationDescriptorIsValid;
	wStream* out;
	int MsOutSize = 0;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (transferDir == 0)
	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "urb_select_configuration: unsupported transfer out");
		return ERROR_INVALID_PARAMETER;
	}

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT8(s, ConfigurationDescriptorIsValid);
	Stream_Seek(s, 3); 
	Stream_Read_UINT32(s, NumInterfaces);

	
	if (ConfigurationDescriptorIsValid)
	{
		
		MsConfig = msusb_msconfig_read(s, NumInterfaces);

		if (!MsConfig)
			return ERROR_INVALID_DATA;

		
		pdev->select_configuration(pdev, MsConfig->bConfigurationValue);
		
		func_select_all_interface_for_msconfig(pdev, MsConfig);
		
		if (!pdev->complete_msconfig_setup(pdev, MsConfig))
		{
			msusb_msconfig_free(MsConfig);
			MsConfig = NULL;
		}
	}

	if (MsConfig)
		MsOutSize = MsConfig->MsOutSize;

	if (MsOutSize > 0)
		out_size = 36 + MsOutSize;
	else out_size = 44;

	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Write_UINT32(out, InterfaceId);            
	Stream_Write_UINT32(out, MessageId);              
	Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA); 
	Stream_Write_UINT32(out, RequestId);              

	if (MsOutSize > 0)
	{
		
		Stream_Write_UINT32(out, 8 + MsOutSize);
		
		Stream_Write_UINT16(out, 8 + MsOutSize);
	}
	else {
		Stream_Write_UINT32(out, 16);
		Stream_Write_UINT16(out, 16);
	}

	
	Stream_Write_UINT16(out, TS_URB_SELECT_CONFIGURATION);
	Stream_Write_UINT32(out, usbd_status); 

	
	if (MsOutSize > 0)
		msusb_msconfig_write(MsConfig, out);
	else {
		Stream_Write_UINT32(out, 0);             
		Stream_Write_UINT32(out, NumInterfaces); 
	}

	Stream_Write_UINT32(out, 0); 
	Stream_Write_UINT32(out, 0); 

	if (!noAck)
		return stream_write_and_free(callback->plugin, callback->channel, out);
	else Stream_Free(out, TRUE);

	return ERROR_SUCCESS;
}

static UINT urb_select_interface(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	MSUSB_CONFIG_DESCRIPTOR* MsConfig;
	MSUSB_INTERFACE_DESCRIPTOR* MsInterface;
	UINT32 out_size, InterfaceId, ConfigurationHandle;
	UINT32 OutputBufferSize;
	BYTE InterfaceNumber;
	wStream* out;
	UINT32 interface_size;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (transferDir == 0)
	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "urb_select_interface: not support transfer out");
		return ERROR_INVALID_PARAMETER;
	}

	if (Stream_GetRemainingLength(s) < 4)
		return ERROR_INVALID_DATA;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT32(s, ConfigurationHandle);
	MsInterface = msusb_msinterface_read(s);

	if ((Stream_GetRemainingLength(s) < 4) || !MsInterface)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, OutputBufferSize);
	pdev->select_interface(pdev, MsInterface->InterfaceNumber, MsInterface->AlternateSetting);
	
	MsConfig = pdev->get_MsConfig(pdev);
	InterfaceNumber = MsInterface->InterfaceNumber;
	if (!msusb_msinterface_replace(MsConfig, InterfaceNumber, MsInterface))
	{
		msusb_msconfig_free(MsConfig);
		return ERROR_BAD_CONFIGURATION;
	}
	
	if (!pdev->complete_msconfig_setup(pdev, MsConfig))
	{
		msusb_msconfig_free(MsConfig);
		return ERROR_BAD_CONFIGURATION;
	}
	MsInterface = MsConfig->MsInterfaces[InterfaceNumber];
	interface_size = 16 + (MsInterface->NumberOfPipes * 20);
	out_size = 36 + interface_size;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Write_UINT32(out, InterfaceId);            
	Stream_Write_UINT32(out, MessageId);              
	Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA); 
	Stream_Write_UINT32(out, RequestId);              
	Stream_Write_UINT32(out, 8 + interface_size);     
	
	Stream_Write_UINT16(out, 8 + interface_size); 
	
	Stream_Write_UINT16(out, TS_URB_SELECT_INTERFACE);
	Stream_Write_UINT32(out, USBD_STATUS_SUCCESS); 
	
	msusb_msinterface_write(MsInterface, out);
	Stream_Write_UINT32(out, 0); 
	Stream_Write_UINT32(out, 0); 

	if (!noAck)
		return stream_write_and_free(callback->plugin, callback->channel, out);
	else Stream_Free(out, TRUE);

	return ERROR_SUCCESS;
}

static UINT urb_control_transfer(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir, int External)

{
	UINT32 out_size, InterfaceId, EndpointAddress, PipeHandle;
	UINT32 TransferFlags, OutputBufferSize, usbd_status, Timeout;
	BYTE bmRequestType, Request;
	UINT16 Value, Index, length;
	BYTE* buffer;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT32(s, PipeHandle);
	Stream_Read_UINT32(s, TransferFlags); 
	EndpointAddress = (PipeHandle & 0x000000ff);
	Timeout = 2000;

	switch (External)
	{
		case URB_CONTROL_TRANSFER_EXTERNAL:
			if (Stream_GetRemainingLength(s) < 4)
				return ERROR_INVALID_DATA;

			Stream_Read_UINT32(s, Timeout); 
			break;

		case URB_CONTROL_TRANSFER_NONEXTERNAL:
			break;
	}

	
	if (Stream_GetRemainingLength(s) < 12)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT8(s, bmRequestType);
	Stream_Read_UINT8(s, Request);
	Stream_Read_UINT16(s, Value);
	Stream_Read_UINT16(s, Index);
	Stream_Read_UINT16(s, length);
	Stream_Read_UINT32(s, OutputBufferSize);

	if (length != OutputBufferSize)
	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "urb_control_transfer ERROR: buf != length");
		return ERROR_INVALID_DATA;
	}

	out_size = 36 + OutputBufferSize;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);
	
	buffer = Stream_Pointer(out);

	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
		Stream_Copy(s, out, OutputBufferSize);

	
	if (!pdev->control_transfer(pdev, RequestId, EndpointAddress, TransferFlags, bmRequestType, Request, Value, Index, &usbd_status, &OutputBufferSize, buffer, Timeout))

	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "control_transfer failed");
		Stream_Free(out, TRUE);
		return ERROR_INTERNAL_ERROR;
	}

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}

static void urb_bulk_transfer_cb(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* out, UINT32 InterfaceId, BOOL noAck, UINT32 MessageId, UINT32 RequestId, UINT32 NumberOfPackets, UINT32 status, UINT32 StartFrame, UINT32 ErrorCount, UINT32 OutputBufferSize)


{
	if (!pdev->isChannelClosed(pdev))
		urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, status, OutputBufferSize);
	else Stream_Free(out, TRUE);
}

static UINT urb_bulk_or_interrupt_transfer(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	UINT32 EndpointAddress, PipeHandle;
	UINT32 TransferFlags, OutputBufferSize;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!pdev || !callback || !s || !udevman)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 12)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, PipeHandle);
	Stream_Read_UINT32(s, TransferFlags); 
	Stream_Read_UINT32(s, OutputBufferSize);
	EndpointAddress = (PipeHandle & 0x000000ff);
	
	return pdev->bulk_or_interrupt_transfer(pdev, callback, MessageId, RequestId, EndpointAddress, TransferFlags, noAck, OutputBufferSize, urb_bulk_transfer_cb, 10000);

}

static void urb_isoch_transfer_cb(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* out, UINT32 InterfaceId, BOOL noAck, UINT32 MessageId, UINT32 RequestId, UINT32 NumberOfPackets, UINT32 status, UINT32 StartFrame, UINT32 ErrorCount, UINT32 OutputBufferSize)


{
	if (!noAck)
	{
		UINT32 packetSize = (status == 0) ? NumberOfPackets * 12 : 0;
		Stream_SetPosition(out, 0);
		
		Stream_Write_UINT32(out, InterfaceId); 
		Stream_Write_UINT32(out, MessageId);   

		if (OutputBufferSize == 0)
			Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA); 
		else Stream_Write_UINT32(out, URB_COMPLETION);

		Stream_Write_UINT32(out, RequestId);       
		Stream_Write_UINT32(out, 20 + packetSize); 
		
		Stream_Write_UINT16(out, 20 + packetSize); 
		Stream_Write_UINT16(out, 0);               
		Stream_Write_UINT32(out, status);          
		Stream_Write_UINT32(out, StartFrame);      

		if (status == 0)
		{
			
			Stream_Write_UINT32(out, NumberOfPackets);
			Stream_Write_UINT32(out, ErrorCount); 
			Stream_Seek(out, packetSize);
		}
		else {
			Stream_Write_UINT32(out, 0);          
			Stream_Write_UINT32(out, ErrorCount); 
		}

		Stream_Write_UINT32(out, 0);                
		Stream_Write_UINT32(out, OutputBufferSize); 
		Stream_Seek(out, OutputBufferSize);

		if (!pdev->isChannelClosed(pdev))
			callback->channel->Write(callback->channel, Stream_GetPosition(out), Stream_Buffer(out), NULL);
	}

	Stream_Free(out, TRUE);
}

static UINT urb_isoch_transfer(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	UINT32 EndpointAddress;
	UINT32 PipeHandle, TransferFlags, StartFrame, NumberOfPackets;
	UINT32 ErrorCount, OutputBufferSize;
	BYTE* packetDescriptorData;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!pdev || !callback || !udevman)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 20)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, PipeHandle);
	EndpointAddress = (PipeHandle & 0x000000ff);
	Stream_Read_UINT32(s, TransferFlags);   
	Stream_Read_UINT32(s, StartFrame);      
	Stream_Read_UINT32(s, NumberOfPackets); 
	Stream_Read_UINT32(s, ErrorCount);      

	if (Stream_GetRemainingLength(s) < NumberOfPackets * 12 + 4)
		return ERROR_INVALID_DATA;

	packetDescriptorData = Stream_Pointer(s);
	Stream_Seek(s, NumberOfPackets * 12);
	Stream_Read_UINT32(s, OutputBufferSize);
	return pdev->isoch_transfer( pdev, callback, MessageId, RequestId, EndpointAddress, TransferFlags, StartFrame, ErrorCount, noAck, packetDescriptorData, NumberOfPackets, OutputBufferSize, (transferDir == USBD_TRANSFER_DIRECTION_OUT) ? Stream_Pointer(s) : NULL, urb_isoch_transfer_cb, 2000);



}

static UINT urb_control_descriptor_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, BYTE func_recipient, int transferDir)

{
	UINT32 out_size, InterfaceId, OutputBufferSize, usbd_status;
	BYTE bmRequestType, desc_index, desc_type;
	UINT16 langId;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT8(s, desc_index);
	Stream_Read_UINT8(s, desc_type);
	Stream_Read_UINT16(s, langId);
	Stream_Read_UINT32(s, OutputBufferSize);

	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
	{
		if (Stream_GetRemainingLength(s) < OutputBufferSize)
			return ERROR_INVALID_DATA;
	}

	out_size = 36 + OutputBufferSize;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);
	bmRequestType = func_recipient;

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_IN:
			bmRequestType |= 0x80;
			break;

		case USBD_TRANSFER_DIRECTION_OUT:
			bmRequestType |= 0x00;
			Stream_Copy(s, out, OutputBufferSize);
			Stream_Rewind(out, OutputBufferSize);
			break;

		default:
			WLog_Print(urbdrc->log, WLOG_DEBUG, "get error transferDir");
			OutputBufferSize = 0;
			usbd_status = USBD_STATUS_STALL_PID;
			break;
	}

	
	if (!pdev->control_transfer(pdev, RequestId, 0, 0, bmRequestType, 0x06, (desc_type << 8) | desc_index, langId, &usbd_status, &OutputBufferSize, Stream_Pointer(out), 1000))


	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "get_descriptor failed");
		Stream_Free(out, TRUE);
		return ERROR_INTERNAL_ERROR;
	}

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}

static UINT urb_control_get_status_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, BYTE func_recipient, int transferDir)

{
	UINT32 out_size, InterfaceId, OutputBufferSize, usbd_status;
	UINT16 Index;
	BYTE bmRequestType;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (transferDir == 0)
	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "urb_control_get_status_request: transfer out not supported");
		return ERROR_INVALID_PARAMETER;
	}

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT16(s, Index); 
	Stream_Seek(s, 2);
	Stream_Read_UINT32(s, OutputBufferSize);
	out_size = 36 + OutputBufferSize;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);
	bmRequestType = func_recipient | 0x80;

	if (!pdev->control_transfer(pdev, RequestId, 0, 0, bmRequestType, 0x00,  0, Index, &usbd_status, &OutputBufferSize, Stream_Pointer(out), 1000))

	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "control_transfer failed");
		Stream_Free(out, TRUE);
		return ERROR_INTERNAL_ERROR;
	}

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}

static UINT urb_control_vendor_or_class_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, BYTE func_type, BYTE func_recipient, int transferDir)


{
	UINT32 out_size, InterfaceId, TransferFlags, usbd_status;
	UINT32 OutputBufferSize;
	BYTE ReqTypeReservedBits, Request, bmRequestType;
	UINT16 Value, Index, Padding;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 16)
		return ERROR_INVALID_DATA;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT32(s, TransferFlags);      
	Stream_Read_UINT8(s, ReqTypeReservedBits); 
	Stream_Read_UINT8(s, Request);             
	Stream_Read_UINT16(s, Value);              
	Stream_Read_UINT16(s, Index);              
	Stream_Read_UINT16(s, Padding);            
	Stream_Read_UINT32(s, OutputBufferSize);

	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
	{
		if (Stream_GetRemainingLength(s) < OutputBufferSize)
			return ERROR_INVALID_DATA;
	}

	out_size = 36 + OutputBufferSize;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);

	
	if (transferDir == USBD_TRANSFER_DIRECTION_OUT)
	{
		Stream_Copy(s, out, OutputBufferSize);
		Stream_Rewind(out, OutputBufferSize);
	}

	
	bmRequestType = func_type | func_recipient;

	if (TransferFlags & USBD_TRANSFER_DIRECTION)
		bmRequestType |= 0x80;

	WLog_Print(urbdrc->log, WLOG_DEBUG, "RequestId 0x%" PRIx32 " TransferFlags: 0x%" PRIx32 " ReqTypeReservedBits: 0x%" PRIx8 " " "Request:0x%" PRIx8 " Value: 0x%" PRIx16 " Index: 0x%" PRIx16 " OutputBufferSize: 0x%" PRIx32 " bmRequestType: 0x%" PRIx8, RequestId, TransferFlags, ReqTypeReservedBits, Request, Value, Index, OutputBufferSize, bmRequestType);






	if (!pdev->control_transfer(pdev, RequestId, 0, 0, bmRequestType, Request, Value, Index, &usbd_status, &OutputBufferSize, Stream_Pointer(out), 2000))
	{
		WLog_Print(urbdrc->log, WLOG_ERROR, "control_transfer failed");
		Stream_Free(out, TRUE);
		return ERROR_INTERNAL_ERROR;
	}

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}

static UINT urb_os_feature_descriptor_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	UINT32 out_size, InterfaceId, OutputBufferSize, usbd_status;
	BYTE Recipient, InterfaceNumber, Ms_PageIndex;
	UINT16 Ms_featureDescIndex;
	wStream* out;
	int ret;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 12)
		return ERROR_INVALID_DATA;

	
	Stream_Read_UINT8(s, Recipient);            
	Recipient = (Recipient & 0x1f);             
	Stream_Read_UINT8(s, InterfaceNumber);      
	Stream_Read_UINT8(s, Ms_PageIndex);         
	Stream_Read_UINT16(s, Ms_featureDescIndex); 
	Stream_Seek(s, 3);                          
	Stream_Read_UINT32(s, OutputBufferSize);

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			if (Stream_GetRemainingLength(s) < OutputBufferSize)
				return ERROR_INVALID_DATA;

			break;

		default:
			break;
	}

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	out_size = 36 + OutputBufferSize;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			Stream_Copy(s, out, OutputBufferSize);
			Stream_Rewind(out, OutputBufferSize);
			break;

		case USBD_TRANSFER_DIRECTION_IN:
			break;
	}

	WLog_Print(urbdrc->log, WLOG_DEBUG, "Ms descriptor arg: Recipient:0x%" PRIx8 ", " "InterfaceNumber:0x%" PRIx8 ", Ms_PageIndex:0x%" PRIx8 ", " "Ms_featureDescIndex:0x%" PRIx16 ", OutputBufferSize:0x%" PRIx32 "", Recipient, InterfaceNumber, Ms_PageIndex, Ms_featureDescIndex, OutputBufferSize);



	
	ret = pdev->os_feature_descriptor_request(pdev, RequestId, Recipient, InterfaceNumber, Ms_PageIndex, Ms_featureDescIndex, &usbd_status, &OutputBufferSize, Stream_Pointer(out), 1000);


	if (ret < 0)
		WLog_Print(urbdrc->log, WLOG_DEBUG, "os_feature_descriptor_request: error num %d", ret);

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}

static UINT urb_pipe_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir, int action)

{
	UINT32 out_size, InterfaceId, PipeHandle, EndpointAddress;
	UINT32 OutputBufferSize, usbd_status = 0;
	wStream* out;
	UINT32 ret = USBD_STATUS_REQUEST_FAILED;
	int rc;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	if (transferDir == 0)
	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "urb_pipe_request: not support transfer out");
		return ERROR_INVALID_PARAMETER;
	}

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT32(s, PipeHandle); 
	Stream_Read_UINT32(s, OutputBufferSize);
	EndpointAddress = (PipeHandle & 0x000000ff);

	switch (action)
	{
		case PIPE_CANCEL:
			rc = pdev->control_pipe_request(pdev, RequestId, EndpointAddress, &usbd_status, PIPE_CANCEL);

			if (rc < 0)
				WLog_Print(urbdrc->log, WLOG_DEBUG, "PIPE SET HALT: error %d", ret);
			else ret = USBD_STATUS_SUCCESS;

			break;

		case PIPE_RESET:
			WLog_Print(urbdrc->log, WLOG_DEBUG, "urb_pipe_request: PIPE_RESET ep 0x%" PRIx32 "", EndpointAddress);
			rc = pdev->control_pipe_request(pdev, RequestId, EndpointAddress, &usbd_status, PIPE_RESET);

			if (rc < 0)
				WLog_Print(urbdrc->log, WLOG_DEBUG, "PIPE RESET: error %d", ret);
			else ret = USBD_STATUS_SUCCESS;

			break;

		default:
			WLog_Print(urbdrc->log, WLOG_DEBUG, "urb_pipe_request action: %d not supported", action);
			ret = USBD_STATUS_INVALID_URB_FUNCTION;
			break;
	}

	
	out_size = 36;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, ret, 0);
}

static UINT urb_get_current_frame_number(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	UINT32 out_size, InterfaceId, OutputBufferSize;
	UINT32 dummy_frames;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 4)
		return ERROR_INVALID_DATA;

	if (transferDir == 0)
	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "urb_get_current_frame_number: not support transfer out");
		return ERROR_INVALID_PARAMETER;
	}

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT32(s, OutputBufferSize);
	
	dummy_frames = GetTickCount();
	out_size = 40;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Write_UINT32(out, InterfaceId); 
	Stream_Write_UINT32(out, MessageId);   
	Stream_Write_UINT32(out, URB_COMPLETION_NO_DATA);
	Stream_Write_UINT32(out, RequestId); 
	Stream_Write_UINT32(out, 12);        
	
	Stream_Write_UINT16(out, 12); 
	
	Stream_Write_UINT16(out, TS_URB_GET_CURRENT_FRAME_NUMBER);
	Stream_Write_UINT32(out, USBD_STATUS_SUCCESS); 
	Stream_Write_UINT32(out, dummy_frames);        
	Stream_Write_UINT32(out, 0);                   
	Stream_Write_UINT32(out, 0);                   

	if (!noAck)
		return stream_write_and_free(callback->plugin, callback->channel, out);
	else Stream_Free(out, TRUE);

	return ERROR_SUCCESS;
}


static UINT urb_control_get_configuration_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	UINT32 out_size, InterfaceId, OutputBufferSize, usbd_status;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (transferDir == 0)
	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "urb_control_get_configuration_request:" " not support transfer out");

		return ERROR_INVALID_PARAMETER;
	}

	if (Stream_GetRemainingLength(s) < 4)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, OutputBufferSize);
	out_size = 36 + OutputBufferSize;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);
	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));

	if (!pdev->control_transfer(pdev, RequestId, 0, 0, 0x80 | 0x00, 0x08, 0, 0, &usbd_status, &OutputBufferSize, Stream_Pointer(out), 1000))

	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "control_transfer failed");
		Stream_Free(out, TRUE);
		return ERROR_INTERNAL_ERROR;
	}

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}


static UINT urb_control_get_interface_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	UINT32 out_size, InterfaceId, OutputBufferSize, usbd_status;
	UINT16 interface;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	if (transferDir == 0)
	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "urb_control_get_interface_request: not support transfer out");
		return ERROR_INVALID_PARAMETER;
	}

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT16(s, interface);
	Stream_Seek(s, 2);
	Stream_Read_UINT32(s, OutputBufferSize);
	out_size = 36 + OutputBufferSize;
	out = Stream_New(NULL, out_size);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);

	if (!pdev->control_transfer( pdev, RequestId, 0, 0, 0x80 | 0x01, 0x0A, 0, interface, &usbd_status, &OutputBufferSize, Stream_Pointer(out), 1000))

	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "control_transfer failed");
		Stream_Free(out, TRUE);
		return ERROR_INTERNAL_ERROR;
	}

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}

static UINT urb_control_feature_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 RequestField, UINT32 MessageId, IUDEVMAN* udevman, BYTE func_recipient, BYTE command, int transferDir)


{
	UINT32 InterfaceId, OutputBufferSize, usbd_status;
	UINT16 FeatureSelector, Index;
	BYTE bmRequestType, bmRequest;
	wStream* out;
	URBDRC_PLUGIN* urbdrc;
	const BOOL noAck = (RequestField & 0x80000000U) != 0;
	const UINT32 RequestId = RequestField & 0x7FFFFFFF;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INVALID_DATA;

	InterfaceId = ((STREAM_ID_PROXY << 30) | pdev->get_ReqCompletion(pdev));
	Stream_Read_UINT16(s, FeatureSelector);
	Stream_Read_UINT16(s, Index);
	Stream_Read_UINT32(s, OutputBufferSize);

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			if (Stream_GetRemainingLength(s) < OutputBufferSize)
				return ERROR_INVALID_DATA;

			break;

		default:
			break;
	}

	out = Stream_New(NULL, 36 + OutputBufferSize);

	if (!out)
		return ERROR_OUTOFMEMORY;

	Stream_Seek(out, 36);
	bmRequestType = func_recipient;

	switch (transferDir)
	{
		case USBD_TRANSFER_DIRECTION_OUT:
			WLog_Print(urbdrc->log, WLOG_ERROR, "Function urb_control_feature_request: OUT Unchecked");
			Stream_Copy(s, out, OutputBufferSize);
			Stream_Rewind(out, OutputBufferSize);
			bmRequestType |= 0x00;
			break;

		case USBD_TRANSFER_DIRECTION_IN:
			bmRequestType |= 0x80;
			break;
	}

	switch (command)
	{
		case URB_SET_FEATURE:
			bmRequest = 0x03; 
			break;

		case URB_CLEAR_FEATURE:
			bmRequest = 0x01; 
			break;

		default:
			WLog_Print(urbdrc->log, WLOG_ERROR, "urb_control_feature_request: Error Command 0x%02" PRIx8 "", command);
			Stream_Free(out, TRUE);
			return ERROR_INTERNAL_ERROR;
	}

	if (!pdev->control_transfer(pdev, RequestId, 0, 0, bmRequestType, bmRequest, FeatureSelector, Index, &usbd_status, &OutputBufferSize, Stream_Pointer(out), 1000))
	{
		WLog_Print(urbdrc->log, WLOG_DEBUG, "feature control transfer failed");
		Stream_Free(out, TRUE);
		return ERROR_INTERNAL_ERROR;
	}

	return urb_write_completion(pdev, callback, noAck, out, InterfaceId, MessageId, RequestId, usbd_status, OutputBufferSize);
}

static UINT urbdrc_process_transfer_request(IUDEVICE* pdev, URBDRC_CHANNEL_CALLBACK* callback, wStream* s, UINT32 MessageId, IUDEVMAN* udevman, int transferDir)

{
	UINT32 CbTsUrb;
	UINT16 Size;
	UINT16 URB_Function;
	UINT32 RequestId;
	UINT error = ERROR_INTERNAL_ERROR;
	URBDRC_PLUGIN* urbdrc;

	if (!callback || !s || !udevman || !pdev)
		return ERROR_INVALID_PARAMETER;

	urbdrc = (URBDRC_PLUGIN*)callback->plugin;

	if (!urbdrc)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 12)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, CbTsUrb); 
	Stream_Read_UINT16(s, Size);    
	Stream_Read_UINT16(s, URB_Function);
	Stream_Read_UINT32(s, RequestId);
	WLog_Print(urbdrc->log, WLOG_DEBUG, "URB %s[" PRIu16 "]", urb_function_string(URB_Function), URB_Function);

	switch (URB_Function)
	{
		case TS_URB_SELECT_CONFIGURATION: 
			error = urb_select_configuration(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_SELECT_INTERFACE: 
			error = urb_select_interface(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_PIPE_REQUEST: 
			error = urb_pipe_request(pdev, callback, s, RequestId, MessageId, udevman, transferDir, PIPE_CANCEL);
			break;

		case TS_URB_TAKE_FRAME_LENGTH_CONTROL: 
			
			break;

		case TS_URB_RELEASE_FRAME_LENGTH_CONTROL: 
			
			break;

		case TS_URB_GET_FRAME_LENGTH: 
			
			break;

		case TS_URB_SET_FRAME_LENGTH: 
			
			break;

		case TS_URB_GET_CURRENT_FRAME_NUMBER: 
			error = urb_get_current_frame_number(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_CONTROL_TRANSFER: 
			error = urb_control_transfer(pdev, callback, s, RequestId, MessageId, udevman, transferDir, URB_CONTROL_TRANSFER_NONEXTERNAL);
			break;

		case TS_URB_BULK_OR_INTERRUPT_TRANSFER: 
			error = urb_bulk_or_interrupt_transfer(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_ISOCH_TRANSFER: 
			error = urb_isoch_transfer(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_GET_DESCRIPTOR_FROM_DEVICE: 
			error = urb_control_descriptor_request(pdev, callback, s, RequestId, MessageId, udevman, 0x00, transferDir);
			break;

		case TS_URB_SET_DESCRIPTOR_TO_DEVICE: 
			error = urb_control_descriptor_request(pdev, callback, s, RequestId, MessageId, udevman, 0x00, transferDir);
			break;

		case TS_URB_SET_FEATURE_TO_DEVICE: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x00, URB_SET_FEATURE, transferDir);
			break;

		case TS_URB_SET_FEATURE_TO_INTERFACE: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x01, URB_SET_FEATURE, transferDir);
			break;

		case TS_URB_SET_FEATURE_TO_ENDPOINT: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x02, URB_SET_FEATURE, transferDir);
			break;

		case TS_URB_CLEAR_FEATURE_TO_DEVICE: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x00, URB_CLEAR_FEATURE, transferDir);
			break;

		case TS_URB_CLEAR_FEATURE_TO_INTERFACE: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x01, URB_CLEAR_FEATURE, transferDir);
			break;

		case TS_URB_CLEAR_FEATURE_TO_ENDPOINT: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x02, URB_CLEAR_FEATURE, transferDir);
			break;

		case TS_URB_GET_STATUS_FROM_DEVICE: 
			error = urb_control_get_status_request(pdev, callback, s, RequestId, MessageId, udevman, 0x00, transferDir);
			break;

		case TS_URB_GET_STATUS_FROM_INTERFACE: 
			error = urb_control_get_status_request(pdev, callback, s, RequestId, MessageId, udevman, 0x01, transferDir);
			break;

		case TS_URB_GET_STATUS_FROM_ENDPOINT: 
			error = urb_control_get_status_request(pdev, callback, s, RequestId, MessageId, udevman, 0x02, transferDir);
			break;

		case TS_URB_RESERVED_0X0016: 
			break;

		case TS_URB_VENDOR_DEVICE: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x02 << 5), 0x00, transferDir);

			break;

		case TS_URB_VENDOR_INTERFACE: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x02 << 5), 0x01, transferDir);

			break;

		case TS_URB_VENDOR_ENDPOINT: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x02 << 5), 0x02, transferDir);

			break;

		case TS_URB_CLASS_DEVICE: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x01 << 5), 0x00, transferDir);

			break;

		case TS_URB_CLASS_INTERFACE: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x01 << 5), 0x01, transferDir);

			break;

		case TS_URB_CLASS_ENDPOINT: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x01 << 5), 0x02, transferDir);

			break;

		case TS_URB_RESERVE_0X001D: 
			break;

		case TS_URB_SYNC_RESET_PIPE_AND_CLEAR_STALL: 
			error = urb_pipe_request(pdev, callback, s, RequestId, MessageId, udevman, transferDir, PIPE_RESET);
			break;

		case TS_URB_CLASS_OTHER: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x01 << 5), 0x03, transferDir);

			break;

		case TS_URB_VENDOR_OTHER: 
			error = urb_control_vendor_or_class_request(pdev, callback, s, RequestId, MessageId, udevman, (0x02 << 5), 0x03, transferDir);

			break;

		case TS_URB_GET_STATUS_FROM_OTHER: 
			error = urb_control_get_status_request(pdev, callback, s, RequestId, MessageId, udevman, 0x03, transferDir);
			break;

		case TS_URB_CLEAR_FEATURE_TO_OTHER: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x03, URB_CLEAR_FEATURE, transferDir);
			break;

		case TS_URB_SET_FEATURE_TO_OTHER: 
			error = urb_control_feature_request(pdev, callback, s, RequestId, MessageId, udevman, 0x03, URB_SET_FEATURE, transferDir);
			break;

		case TS_URB_GET_DESCRIPTOR_FROM_ENDPOINT: 
			error = urb_control_descriptor_request(pdev, callback, s, RequestId, MessageId, udevman, 0x02, transferDir);
			break;

		case TS_URB_SET_DESCRIPTOR_TO_ENDPOINT: 
			error = urb_control_descriptor_request(pdev, callback, s, RequestId, MessageId, udevman, 0x02, transferDir);
			break;

		case TS_URB_CONTROL_GET_CONFIGURATION_REQUEST: 
			error = urb_control_get_configuration_request(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_CONTROL_GET_INTERFACE_REQUEST: 
			error = urb_control_get_interface_request(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_GET_DESCRIPTOR_FROM_INTERFACE: 
			error = urb_control_descriptor_request(pdev, callback, s, RequestId, MessageId, udevman, 0x01, transferDir);
			break;

		case TS_URB_SET_DESCRIPTOR_TO_INTERFACE: 
			error = urb_control_descriptor_request(pdev, callback, s, RequestId, MessageId, udevman, 0x01, transferDir);
			break;

		case TS_URB_GET_OS_FEATURE_DESCRIPTOR_REQUEST: 
			error = urb_os_feature_descriptor_request(pdev, callback, s, RequestId, MessageId, udevman, transferDir);
			break;

		case TS_URB_RESERVE_0X002B: 
		case TS_URB_RESERVE_0X002C: 
		case TS_URB_RESERVE_0X002D: 
		case TS_URB_RESERVE_0X002E: 
		case TS_URB_RESERVE_0X002F: 
			break;

		
		case TS_URB_SYNC_RESET_PIPE: 
			error = urb_pipe_request(pdev, callback, s, RequestId, MessageId, udevman, transferDir, PIPE_RESET);
			break;

		case TS_URB_SYNC_CLEAR_STALL: 
			urb_pipe_request(pdev, callback, s, RequestId, MessageId, udevman, transferDir, PIPE_RESET);
			break;

		case TS_URB_CONTROL_TRANSFER_EX: 
			error = urb_control_transfer(pdev, callback, s, RequestId, MessageId, udevman, transferDir, URB_CONTROL_TRANSFER_EXTERNAL);
			break;

		default:
			WLog_Print(urbdrc->log, WLOG_DEBUG, "URB_Func: %" PRIx16 " is not found!", URB_Function);
			break;
	}

	return error;
}

UINT urbdrc_process_udev_data_transfer(URBDRC_CHANNEL_CALLBACK* callback, URBDRC_PLUGIN* urbdrc, IUDEVMAN* udevman, wStream* data)
{
	UINT32 InterfaceId;
	UINT32 MessageId;
	UINT32 FunctionId;
	IUDEVICE* pdev;
	UINT error = ERROR_INTERNAL_ERROR;
	size_t len;

	if (!urbdrc || !data || !callback || !udevman)
		goto fail;

	len = Stream_GetRemainingLength(data);

	if (len < 8)
		goto fail;

	Stream_Rewind_UINT32(data);

	Stream_Read_UINT32(data, InterfaceId);
	Stream_Read_UINT32(data, MessageId);
	Stream_Read_UINT32(data, FunctionId);

	pdev = udevman->get_udevice_by_UsbDevice(udevman, InterfaceId);

	
	if (pdev == NULL)
	{
		error = ERROR_SUCCESS;
		goto fail;
	}

	
	if (pdev->isChannelClosed(pdev))
	{
		error = ERROR_SUCCESS;
		goto fail;
	}

	
	pdev->detach_kernel_driver(pdev);

	switch (FunctionId)
	{
		case CANCEL_REQUEST:
			error = urbdrc_process_cancel_request(pdev, data, udevman);
			break;

		case REGISTER_REQUEST_CALLBACK:
			error = urbdrc_process_register_request_callback(pdev, callback, data, udevman);
			break;

		case IO_CONTROL:
			error = urbdrc_process_io_control(pdev, callback, data, MessageId, udevman);
			break;

		case INTERNAL_IO_CONTROL:
			error = urbdrc_process_internal_io_control(pdev, callback, data, MessageId, udevman);
			break;

		case QUERY_DEVICE_TEXT:
			error = urbdrc_process_query_device_text(pdev, callback, data, MessageId, udevman);
			break;

		case TRANSFER_IN_REQUEST:
			error = urbdrc_process_transfer_request(pdev, callback, data, MessageId, udevman, USBD_TRANSFER_DIRECTION_IN);
			break;

		case TRANSFER_OUT_REQUEST:
			error = urbdrc_process_transfer_request(pdev, callback, data, MessageId, udevman, USBD_TRANSFER_DIRECTION_OUT);
			break;

		case RETRACT_DEVICE:
			error = urbdrc_process_retract_device_request(pdev, data, udevman);
			break;

		default:
			WLog_Print(urbdrc->log, WLOG_WARN, "urbdrc_process_udev_data_transfer:" " unknown FunctionId 0x%" PRIX32 "", FunctionId);


			break;
	}

fail:
	if (error)
	{
		WLog_WARN(TAG, "USB request failed with %08" PRIx32, error);
	}

	return error;
}
