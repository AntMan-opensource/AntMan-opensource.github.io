



































static void drive_file_fix_path(WCHAR* path)
{
	size_t i;
	size_t length = _wcslen(path);

	for (i = 0; i < length; i++)
	{
		if (path[i] == L'\\')
			path[i] = L'/';
	}



	if ((length == 3) && (path[1] == L':') && (path[2] == L'/'))
		return;



	if ((length == 1) && (path[0] == L'/'))
		return;



	if ((length > 0) && (path[length - 1] == L'/'))
		path[length - 1] = L'\0';
}

static WCHAR* drive_file_combine_fullpath(const WCHAR* base_path, const WCHAR* path, size_t PathLength)
{
	WCHAR* fullpath;
	size_t base_path_length;

	if (!base_path || (!path && (PathLength > 0)))
		return NULL;

	base_path_length = _wcslen(base_path) * 2;
	fullpath = (WCHAR*)calloc(1, base_path_length + PathLength + sizeof(WCHAR));

	if (!fullpath)
	{
		WLog_ERR(TAG, "malloc failed!");
		return NULL;
	}

	CopyMemory(fullpath, base_path, base_path_length);
	if (path)
		CopyMemory((char*)fullpath + base_path_length, path, PathLength);
	drive_file_fix_path(fullpath);
	return fullpath;
}

static BOOL drive_file_remove_dir(const WCHAR* path)
{
	WIN32_FIND_DATAW findFileData;
	BOOL ret = TRUE;
	HANDLE dir;
	WCHAR* fullpath;
	WCHAR* path_slash;
	size_t base_path_length;

	if (!path)
		return FALSE;

	base_path_length = _wcslen(path) * 2;
	path_slash = (WCHAR*)calloc(1, base_path_length + sizeof(WCHAR) * 3);

	if (!path_slash)
	{
		WLog_ERR(TAG, "malloc failed!");
		return FALSE;
	}

	CopyMemory(path_slash, path, base_path_length);
	path_slash[base_path_length / 2] = L'/';
	path_slash[base_path_length / 2 + 1] = L'*';
	DEBUG_WSTR("Search in %s", path_slash);
	dir = FindFirstFileW(path_slash, &findFileData);
	path_slash[base_path_length / 2 + 1] = 0;

	if (dir == INVALID_HANDLE_VALUE)
	{
		free(path_slash);
		return FALSE;
	}

	do {
		size_t len = _wcslen(findFileData.cFileName);

		if ((len == 1 && findFileData.cFileName[0] == L'.') || (len == 2 && findFileData.cFileName[0] == L'.' && findFileData.cFileName[1] == L'.'))
		{
			continue;
		}

		fullpath = drive_file_combine_fullpath(path_slash, findFileData.cFileName, len * 2);
		DEBUG_WSTR("Delete %s", fullpath);

		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			ret = drive_file_remove_dir(fullpath);
		}
		else {
			ret = DeleteFileW(fullpath);
		}

		free(fullpath);

		if (!ret)
			break;
	} while (ret && FindNextFileW(dir, &findFileData) != 0);

	FindClose(dir);

	if (ret)
	{
		if (!RemoveDirectoryW(path))
		{
			ret = FALSE;
		}
	}

	free(path_slash);
	return ret;
}

static BOOL drive_file_set_fullpath(DRIVE_FILE* file, WCHAR* fullpath)
{
	if (!file || !fullpath)
		return FALSE;

	free(file->fullpath);
	file->fullpath = fullpath;
	file->filename = _wcsrchr(file->fullpath, L'/');

	if (file->filename == NULL)
		file->filename = file->fullpath;
	else file->filename += 1;

	return TRUE;
}

static BOOL drive_file_init(DRIVE_FILE* file)
{
	UINT CreateDisposition = 0;
	DWORD dwAttr = GetFileAttributesW(file->fullpath);

	if (dwAttr != INVALID_FILE_ATTRIBUTES)
	{
		
		file->is_dir = (dwAttr & FILE_ATTRIBUTE_DIRECTORY) != 0;

		if (file->is_dir)
		{
			if (file->CreateDisposition == FILE_CREATE)
			{
				SetLastError(ERROR_ALREADY_EXISTS);
				return FALSE;
			}

			if (file->CreateOptions & FILE_NON_DIRECTORY_FILE)
			{
				SetLastError(ERROR_ACCESS_DENIED);
				return FALSE;
			}

			return TRUE;
		}
		else {
			if (file->CreateOptions & FILE_DIRECTORY_FILE)
			{
				SetLastError(ERROR_DIRECTORY);
				return FALSE;
			}
		}
	}
	else {
		file->is_dir = ((file->CreateOptions & FILE_DIRECTORY_FILE) ? TRUE : FALSE);

		if (file->is_dir)
		{
			
			if ((file->CreateDisposition == FILE_OPEN_IF) || (file->CreateDisposition == FILE_CREATE))
			{
				if (CreateDirectoryW(file->fullpath, NULL) != 0)
				{
					return TRUE;
				}
			}

			SetLastError(ERROR_FILE_NOT_FOUND);
			return FALSE;
		}
	}

	if (file->file_handle == INVALID_HANDLE_VALUE)
	{
		switch (file->CreateDisposition)
		{
			case FILE_SUPERSEDE: 
				CreateDisposition = CREATE_ALWAYS;
				break;

			case FILE_OPEN: 
				CreateDisposition = OPEN_EXISTING;
				break;

			case FILE_CREATE: 
				CreateDisposition = CREATE_NEW;
				break;

			case FILE_OPEN_IF: 
				CreateDisposition = OPEN_ALWAYS;
				break;

			case FILE_OVERWRITE: 
				CreateDisposition = TRUNCATE_EXISTING;
				break;

			case FILE_OVERWRITE_IF: 
				CreateDisposition = CREATE_ALWAYS;
				break;

			default:
				break;
		}


		file->SharedAccess = 0;

		file->file_handle = CreateFileW(file->fullpath, file->DesiredAccess, file->SharedAccess, NULL, CreateDisposition, file->FileAttributes, NULL);
	}


	if (file->file_handle == INVALID_HANDLE_VALUE)
	{
		
		DWORD errorMessageID = GetLastError();

		if (errorMessageID != 0)
		{
			LPSTR messageBuffer = NULL;
			size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);



			WLog_ERR(TAG, "Error in drive_file_init: %s %s", messageBuffer, file->fullpath);
			
			LocalFree(messageBuffer);
			
			SetLastError(errorMessageID);
		}
	}


	return file->file_handle != INVALID_HANDLE_VALUE;
}

DRIVE_FILE* drive_file_new(const WCHAR* base_path, const WCHAR* path, UINT32 PathLength, UINT32 id, UINT32 DesiredAccess, UINT32 CreateDisposition, UINT32 CreateOptions, UINT32 FileAttributes, UINT32 SharedAccess)

{
	DRIVE_FILE* file;

	if (!base_path || (!path && (PathLength > 0)))
		return NULL;

	file = (DRIVE_FILE*)calloc(1, sizeof(DRIVE_FILE));

	if (!file)
	{
		WLog_ERR(TAG, "calloc failed!");
		return NULL;
	}

	file->file_handle = INVALID_HANDLE_VALUE;
	file->find_handle = INVALID_HANDLE_VALUE;
	file->id = id;
	file->basepath = base_path;
	file->FileAttributes = FileAttributes;
	file->DesiredAccess = DesiredAccess;
	file->CreateDisposition = CreateDisposition;
	file->CreateOptions = CreateOptions;
	file->SharedAccess = SharedAccess;
	drive_file_set_fullpath(file, drive_file_combine_fullpath(base_path, path, PathLength));

	if (!drive_file_init(file))
	{
		DWORD lastError = GetLastError();
		drive_file_free(file);
		SetLastError(lastError);
		return NULL;
	}

	return file;
}

BOOL drive_file_free(DRIVE_FILE* file)
{
	BOOL rc = FALSE;

	if (!file)
		return FALSE;

	if (file->file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file->file_handle);
		file->file_handle = INVALID_HANDLE_VALUE;
	}

	if (file->find_handle != INVALID_HANDLE_VALUE)
	{
		FindClose(file->find_handle);
		file->find_handle = INVALID_HANDLE_VALUE;
	}

	if (file->delete_pending)
	{
		if (file->is_dir)
		{
			if (!drive_file_remove_dir(file->fullpath))
				goto fail;
		}
		else if (!DeleteFileW(file->fullpath))
			goto fail;
	}

	rc = TRUE;
fail:
	DEBUG_WSTR("Free %s", file->fullpath);
	free(file->fullpath);
	free(file);
	return rc;
}

BOOL drive_file_seek(DRIVE_FILE* file, UINT64 Offset)
{
	LARGE_INTEGER loffset;

	if (!file)
		return FALSE;

	if (Offset > INT64_MAX)
		return FALSE;

	loffset.QuadPart = (LONGLONG)Offset;
	return SetFilePointerEx(file->file_handle, loffset, NULL, FILE_BEGIN);
}

BOOL drive_file_read(DRIVE_FILE* file, BYTE* buffer, UINT32* Length)
{
	UINT32 read;

	if (!file || !buffer || !Length)
		return FALSE;

	DEBUG_WSTR("Read file %s", file->fullpath);

	if (ReadFile(file->file_handle, buffer, *Length, &read, NULL))
	{
		*Length = read;
		return TRUE;
	}

	return FALSE;
}

BOOL drive_file_write(DRIVE_FILE* file, BYTE* buffer, UINT32 Length)
{
	UINT32 written;

	if (!file || !buffer)
		return FALSE;

	DEBUG_WSTR("Write file %s", file->fullpath);

	while (Length > 0)
	{
		if (!WriteFile(file->file_handle, buffer, Length, &written, NULL))
			return FALSE;

		Length -= written;
		buffer += written;
	}

	return TRUE;
}

BOOL drive_file_query_information(DRIVE_FILE* file, UINT32 FsInformationClass, wStream* output)
{
	WIN32_FILE_ATTRIBUTE_DATA fileAttributes;
	DEBUG_WSTR("FindFirstFile %s", file->fullpath);

	if (!file || !output)
		return FALSE;

	if (!GetFileAttributesExW(file->fullpath, GetFileExInfoStandard, &fileAttributes))
		goto out_fail;

	switch (FsInformationClass)
	{
		case FileBasicInformation:

			
			if (!Stream_EnsureRemainingCapacity(output, 4 + 36))
				goto out_fail;

			Stream_Write_UINT32(output, 36); 
			Stream_Write_UINT32(output, fileAttributes.ftCreationTime.dwLowDateTime);
			Stream_Write_UINT32(output, fileAttributes.ftCreationTime.dwHighDateTime);
			Stream_Write_UINT32(output, fileAttributes.ftLastAccessTime.dwLowDateTime);
			Stream_Write_UINT32( output, fileAttributes.ftLastAccessTime.dwHighDateTime);
			Stream_Write_UINT32(output, fileAttributes.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, fileAttributes.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, fileAttributes.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, fileAttributes.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, fileAttributes.dwFileAttributes);       
			
			break;

		case FileStandardInformation:

			
			if (!Stream_EnsureRemainingCapacity(output, 4 + 22))
				goto out_fail;

			Stream_Write_UINT32(output, 22);                           
			Stream_Write_UINT32(output, fileAttributes.nFileSizeLow);  
			Stream_Write_UINT32(output, fileAttributes.nFileSizeHigh); 
			Stream_Write_UINT32(output, fileAttributes.nFileSizeLow);  
			Stream_Write_UINT32(output, fileAttributes.nFileSizeHigh); 
			Stream_Write_UINT32(output, 0);                            
			Stream_Write_UINT8(output, file->delete_pending ? 1 : 0);  
			Stream_Write_UINT8(output, fileAttributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? TRUE : FALSE);

			
			break;

		case FileAttributeTagInformation:

			
			if (!Stream_EnsureRemainingCapacity(output, 4 + 8))
				goto out_fail;

			Stream_Write_UINT32(output, 8);                               
			Stream_Write_UINT32(output, fileAttributes.dwFileAttributes); 
			Stream_Write_UINT32(output, 0);                               
			break;

		default:
			
			goto out_fail;
	}

	return TRUE;
out_fail:
	Stream_Write_UINT32(output, 0); 
	return FALSE;
}

BOOL drive_file_set_information(DRIVE_FILE* file, UINT32 FsInformationClass, UINT32 Length, wStream* input)
{
	INT64 size;
	WCHAR* fullpath;
	ULARGE_INTEGER liCreationTime;
	ULARGE_INTEGER liLastAccessTime;
	ULARGE_INTEGER liLastWriteTime;
	ULARGE_INTEGER liChangeTime;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	FILETIME* pftCreationTime = NULL;
	FILETIME* pftLastAccessTime = NULL;
	FILETIME* pftLastWriteTime = NULL;
	UINT32 FileAttributes;
	UINT32 FileNameLength;
	LARGE_INTEGER liSize;
	UINT8 delete_pending;
	UINT8 ReplaceIfExists;
	DWORD attr;

	if (!file || !input)
		return FALSE;

	switch (FsInformationClass)
	{
		case FileBasicInformation:
			if (Stream_GetRemainingLength(input) < 36)
				return FALSE;

			
			Stream_Read_UINT64(input, liCreationTime.QuadPart);
			Stream_Read_UINT64(input, liLastAccessTime.QuadPart);
			Stream_Read_UINT64(input, liLastWriteTime.QuadPart);
			Stream_Read_UINT64(input, liChangeTime.QuadPart);
			Stream_Read_UINT32(input, FileAttributes);

			if (!PathFileExistsW(file->fullpath))
				return FALSE;

			if (file->file_handle == INVALID_HANDLE_VALUE)
			{
				WLog_ERR(TAG, "Unable to set file time %s (%" PRId32 ")", file->fullpath, GetLastError());
				return FALSE;
			}

			if (liCreationTime.QuadPart != 0)
			{
				ftCreationTime.dwHighDateTime = liCreationTime.u.HighPart;
				ftCreationTime.dwLowDateTime = liCreationTime.u.LowPart;
				pftCreationTime = &ftCreationTime;
			}

			if (liLastAccessTime.QuadPart != 0)
			{
				ftLastAccessTime.dwHighDateTime = liLastAccessTime.u.HighPart;
				ftLastAccessTime.dwLowDateTime = liLastAccessTime.u.LowPart;
				pftLastAccessTime = &ftLastAccessTime;
			}

			if (liLastWriteTime.QuadPart != 0)
			{
				ftLastWriteTime.dwHighDateTime = liLastWriteTime.u.HighPart;
				ftLastWriteTime.dwLowDateTime = liLastWriteTime.u.LowPart;
				pftLastWriteTime = &ftLastWriteTime;
			}

			if (liChangeTime.QuadPart != 0 && liChangeTime.QuadPart > liLastWriteTime.QuadPart)
			{
				ftLastWriteTime.dwHighDateTime = liChangeTime.u.HighPart;
				ftLastWriteTime.dwLowDateTime = liChangeTime.u.LowPart;
				pftLastWriteTime = &ftLastWriteTime;
			}

			DEBUG_WSTR("SetFileTime %s", file->fullpath);

			SetFileAttributesW(file->fullpath, FileAttributes);
			if (!SetFileTime(file->file_handle, pftCreationTime, pftLastAccessTime, pftLastWriteTime))
			{
				WLog_ERR(TAG, "Unable to set file time to %s", file->fullpath);
				return FALSE;
			}

			break;

		case FileEndOfFileInformation:

		
		case FileAllocationInformation:
			if (Stream_GetRemainingLength(input) < 8)
				return FALSE;

			
			Stream_Read_INT64(input, size);

			if (file->file_handle == INVALID_HANDLE_VALUE)
			{
				WLog_ERR(TAG, "Unable to truncate %s to %" PRId64 " (%" PRId32 ")", file->fullpath, size, GetLastError());
				return FALSE;
			}

			liSize.QuadPart = size;

			if (!SetFilePointerEx(file->file_handle, liSize, NULL, FILE_BEGIN))
			{
				WLog_ERR(TAG, "Unable to truncate %s to %d (%" PRId32 ")", file->fullpath, size, GetLastError());
				return FALSE;
			}

			DEBUG_WSTR("Truncate %s", file->fullpath);

			if (SetEndOfFile(file->file_handle) == 0)
			{
				WLog_ERR(TAG, "Unable to truncate %s to %d (%" PRId32 ")", file->fullpath, size, GetLastError());
				return FALSE;
			}

			break;

		case FileDispositionInformation:

			
			
			if (file->is_dir && !PathIsDirectoryEmptyW(file->fullpath))
				break; 

			if (Length)
			{
				if (Stream_GetRemainingLength(input) < 1)
					return FALSE;

				Stream_Read_UINT8(input, delete_pending);
			}
			else delete_pending = 1;

			if (delete_pending)
			{
				DEBUG_WSTR("SetDeletePending %s", file->fullpath);
				attr = GetFileAttributesW(file->fullpath);

				if (attr & FILE_ATTRIBUTE_READONLY)
				{
					SetLastError(ERROR_ACCESS_DENIED);
					return FALSE;
				}
			}

			file->delete_pending = delete_pending;
			break;

		case FileRenameInformation:
			if (Stream_GetRemainingLength(input) < 6)
				return FALSE;

			
			Stream_Read_UINT8(input, ReplaceIfExists);
			Stream_Seek_UINT8(input); 
			Stream_Read_UINT32(input, FileNameLength);

			if (Stream_GetRemainingLength(input) < FileNameLength)
				return FALSE;

			fullpath = drive_file_combine_fullpath(file->basepath, (WCHAR*)Stream_Pointer(input), FileNameLength);

			if (!fullpath)
			{
				WLog_ERR(TAG, "drive_file_combine_fullpath failed!");
				return FALSE;
			}



			if (file->file_handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(file->file_handle);
				file->file_handle = INVALID_HANDLE_VALUE;
			}


			DEBUG_WSTR("MoveFileExW %s", file->fullpath);

			if (MoveFileExW(file->fullpath, fullpath, MOVEFILE_COPY_ALLOWED | (ReplaceIfExists ? MOVEFILE_REPLACE_EXISTING : 0)))

			{
				if (!drive_file_set_fullpath(file, fullpath))
					return FALSE;
			}
			else {
				free(fullpath);
				return FALSE;
			}


			drive_file_init(file);

			break;

		default:
			return FALSE;
	}

	return TRUE;
}

BOOL drive_file_query_directory(DRIVE_FILE* file, UINT32 FsInformationClass, BYTE InitialQuery, const WCHAR* path, UINT32 PathLength, wStream* output)
{
	size_t length;
	WCHAR* ent_path;

	if (!file || !path || !output)
		return FALSE;

	if (InitialQuery != 0)
	{
		
		if (file->find_handle != INVALID_HANDLE_VALUE)
			FindClose(file->find_handle);

		ent_path = drive_file_combine_fullpath(file->basepath, path, PathLength);
		
		file->find_handle = FindFirstFileW(ent_path, &file->find_data);
		free(ent_path);

		if (file->find_handle == INVALID_HANDLE_VALUE)
			goto out_fail;
	}
	else if (!FindNextFileW(file->find_handle, &file->find_data))
		goto out_fail;

	length = _wcslen(file->find_data.cFileName) * 2;

	switch (FsInformationClass)
	{
		case FileDirectoryInformation:

			
			if (!Stream_EnsureRemainingCapacity(output, 4 + 64 + length))
				goto out_fail;

			if (length > UINT32_MAX - 64)
				goto out_fail;

			Stream_Write_UINT32(output, (UINT32)(64 + length)); 
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, file->find_data.ftCreationTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftCreationTime.dwHighDateTime);
			Stream_Write_UINT32( output, file->find_data.ftLastAccessTime.dwLowDateTime);
			Stream_Write_UINT32( output, file->find_data.ftLastAccessTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.nFileSizeLow);           
			Stream_Write_UINT32(output, file->find_data.nFileSizeHigh);          
			Stream_Write_UINT32(output, file->find_data.nFileSizeLow);     
			Stream_Write_UINT32(output, file->find_data.nFileSizeHigh);    
			Stream_Write_UINT32(output, file->find_data.dwFileAttributes); 
			Stream_Write_UINT32(output, (UINT32)length);                   
			Stream_Write(output, file->find_data.cFileName, length);
			break;

		case FileFullDirectoryInformation:

			
			if (!Stream_EnsureRemainingCapacity(output, 4 + 68 + length))
				goto out_fail;

			if (length > UINT32_MAX - 68)
				goto out_fail;

			Stream_Write_UINT32(output, (UINT32)(68 + length)); 
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, file->find_data.ftCreationTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftCreationTime.dwHighDateTime);
			Stream_Write_UINT32( output, file->find_data.ftLastAccessTime.dwLowDateTime);
			Stream_Write_UINT32( output, file->find_data.ftLastAccessTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.nFileSizeLow);           
			Stream_Write_UINT32(output, file->find_data.nFileSizeHigh);          
			Stream_Write_UINT32(output, file->find_data.nFileSizeLow);     
			Stream_Write_UINT32(output, file->find_data.nFileSizeHigh);    
			Stream_Write_UINT32(output, file->find_data.dwFileAttributes); 
			Stream_Write_UINT32(output, (UINT32)length);                   
			Stream_Write_UINT32(output, 0);                                
			Stream_Write(output, file->find_data.cFileName, length);
			break;

		case FileBothDirectoryInformation:

			
			if (!Stream_EnsureRemainingCapacity(output, 4 + 93 + length))
				goto out_fail;

			if (length > UINT32_MAX - 93)
				goto out_fail;

			Stream_Write_UINT32(output, (UINT32)(93 + length)); 
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, file->find_data.ftCreationTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftCreationTime.dwHighDateTime);
			Stream_Write_UINT32( output, file->find_data.ftLastAccessTime.dwLowDateTime);
			Stream_Write_UINT32( output, file->find_data.ftLastAccessTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwLowDateTime);
			Stream_Write_UINT32(output, file->find_data.ftLastWriteTime.dwHighDateTime);
			Stream_Write_UINT32(output, file->find_data.nFileSizeLow);           
			Stream_Write_UINT32(output, file->find_data.nFileSizeHigh);          
			Stream_Write_UINT32(output, file->find_data.nFileSizeLow);     
			Stream_Write_UINT32(output, file->find_data.nFileSizeHigh);    
			Stream_Write_UINT32(output, file->find_data.dwFileAttributes); 
			Stream_Write_UINT32(output, (UINT32)length);                   
			Stream_Write_UINT32(output, 0);                                
			Stream_Write_UINT8(output, 0);                                 
			
			Stream_Zero(output, 24); 
			Stream_Write(output, file->find_data.cFileName, length);
			break;

		case FileNamesInformation:

			
			if (!Stream_EnsureRemainingCapacity(output, 4 + 12 + length))
				goto out_fail;

			if (length > UINT32_MAX - 12)
				goto out_fail;

			Stream_Write_UINT32(output, (UINT32)(12 + length)); 
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, 0);                     
			Stream_Write_UINT32(output, (UINT32)length);        
			Stream_Write(output, file->find_data.cFileName, length);
			break;

		default:
			WLog_ERR(TAG, "unhandled FsInformationClass %" PRIu32, FsInformationClass);
			
			goto out_fail;
	}

	return TRUE;
out_fail:
	Stream_Write_UINT32(output, 0); 
	Stream_Write_UINT8(output, 0);  
	return FALSE;
}
