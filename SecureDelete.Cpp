#define _CRT_SECURE_NO_DEPRECATE
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// This source implements a secure delete function for 
// Windows NT/2K. It even works on WinNT compressed, encrypted 
// and sparse files.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.H>
#include <TChar.H>
#include <StdIO.H>
#include <Time.H>
#include "Defrag.H"
#include "SecureDelete.H"
#include <VersionHelpers.h>

/*
#ifdef _INTERFACE_APP
	#include "../../Interface/Resources/Resource.H"
	#include "../../Interface/Source/Entry.H"
#elif _SELFEXTRACTOR_APP
	#include "../../Other/Resources/Resource.H"
	#include "../../Other/Source/Entry.H"
	#else
	#error "You must define either _INTERFACE_APP or _SELFEXTRACTOR_APP"
#endif
*/

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define LLINVALID		((ULONGLONG) -1)
#define	FILEMAPSIZE		(16384+2)
#define CLEANBUFSIZE	65536

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool bSecureDeleteSupported = false;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void PrintNtError(UINT uStatus);
bool ScanFile(HANDLE VolumeHandle, DWORD ClusterSize, HANDLE FileHandle, bool *ReallyCompressed, bool *ZappedFile, DWORD dwNumPasses);
bool SecureOverwrite(HANDLE FileHandle, unsigned __int64 Length, DWORD dwNumPasses);
bool InitSecureDelete(void);
bool SecureDelete(const char *sFileName, long FileLengthHi, unsigned long FileLengthLo, DWORD dwNumPasses);
bool OverwriteFileName(const char *sFileName, char *sLastFileName);
bool SecureDeleteCompressed(const char *sFileName, DWORD dwNumPasses);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//----------------------------------------------------------------------
//
// PrintNtError
//
// Formats an error message for the last native error.
//
//----------------------------------------------------------------------
void PrintNtError(UINT uStatus)
{
	char *sErrMsg = NULL;

	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, RtlNtStatusToDosError(uStatus), 
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
			(LPTSTR) &sErrMsg, 0, NULL);

	//FIXFIX: Handle error.
	//ThrowFatalError(sErrMsg);

	LocalFree(sErrMsg);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//--------------------------------------------------------------------
//
// PrintWin32Error
// 
// Translates a Win32 error into a text equivalent
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void PrintWin32Error( DWORD ErrorCode )
{
	LPVOID lpMsgBuf;

	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
					NULL, ErrorCode, 
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPTSTR) &lpMsgBuf, 0, NULL );
	printf("%s\n", (char*)lpMsgBuf );
	LocalFree( lpMsgBuf );
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// OverwriteFileName
//
// Securely deletes a file's original name by renaming it several
// times. This works by changing each non-'.' character in the file's
// name to successive alphabetic characters, thus overwriting the
// name 26 times.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool OverwriteFileName(const char *sFileName, char *sLastFileName)
{
	char sNewName[MAX_PATH];
	char *sLastSlash;
	size_t i, j, index;

	strcpy(sLastFileName, sFileName);
	sLastSlash = strrchr(sLastFileName, '\\');
	index = (sLastSlash - sLastFileName) / sizeof(char);

	// Loop through each letter in the English alphabet
	strcpy(sNewName, sFileName);
	for(i = 0; i < 26; i++)
	{
		// Replace each non-'.' character with the same letter
		for(j = index+1 ; j < strlen(sFileName); j++)
		{
			if(sFileName[j] != '.')
			{
				sNewName[j] = (TCHAR) i + 'A';
			}
		}

		// Got a new name, so rename file
		if(!MoveFile(sLastFileName, sNewName))
		{
			// Bail on error
			return false;
		}

		strcpy(sLastFileName, sNewName);
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// SecureOverwrite
//
// This function implements a secure sanitize of rigid (removable 
// and fixed) disk media as per the Department of Defense clearing 
// and sanitizing standard: DOD 5220.22-M
// 
// The standard states that hard disk media is sanitized by 
// overwriting with a character, then the character's complement,
// and then a random character. Note that the standard specifically
// states that this method is not suitable for TOP SECRET information.
// TOP SECRET data sanitizing is only achievable by a Type 1 or 2 
// degauss of the disk, or by disintegrating, incinerating, 
// pulverizing, shredding, or melting the disk.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureOverwrite( HANDLE FileHandle, unsigned __int64 Length, DWORD dwNumPasses)
{
	static PBYTE cleanBuffer[3];
	static bool	buffersAllocated = false;

	DWORD			i, j, passes;
	ULONGLONG		totalWritten;
	ULONG			bytesWritten, bytesToWrite;
	LARGE_INTEGER	seekLength;

	// Allocate our cleaning buffers if necessary (we just let program exit free the buffers).
	if( !buffersAllocated )
	{
		// Seed the random number generator
		srand( (unsigned)time( NULL ) );
	
		for( i = 0; i < 3; i++ )
		{
			cleanBuffer[i] = (PBYTE) VirtualAlloc( NULL, CLEANBUFSIZE, MEM_COMMIT, PAGE_READWRITE );
			if( !cleanBuffer[i] )
			{
				for( j = 0; j < i; j++ ) {

					VirtualFree( cleanBuffer[j], 0, MEM_RELEASE );
				}
				return false;
			}

			// Fill each buffer with a different signature
			switch( i )
			{
				case 0:
					// do nothing - buffer is zero-filled by Windows
					memset(cleanBuffer[i], 0, CLEANBUFSIZE);
					break;
				case 1:
					// fill with complement of 0 - 0xFF
					memset( cleanBuffer[i], 0xFF, CLEANBUFSIZE );
					break;
				case 2:
					// fill with a random value
					for( j = 0; j < CLEANBUFSIZE; j++ ) cleanBuffer[i][j] = (BYTE) rand();
					break;
			}
		}	
		buffersAllocated = true;
	}

	// Do the overwrite
	for( passes = 0; passes < dwNumPasses; passes++ )
	{

		if( passes != 0 )
		{

			seekLength.QuadPart = -(LONGLONG) Length;
			SetFilePointer( FileHandle, seekLength.LowPart, &seekLength.HighPart, FILE_CURRENT );
		}

		for( i = 0; i < 3; i++ )
		{
			// Move back to the start of where we're overwriting
			if( i != 0 )
			{

				seekLength.QuadPart = -(LONGLONG) Length;
				SetFilePointer( FileHandle, seekLength.LowPart, &seekLength.HighPart, FILE_CURRENT );
			}

			// Loop and overwrite
			totalWritten = 0;
			while( totalWritten < Length )
			{
				if( Length - totalWritten > 1024*1024)
				{
					bytesToWrite = 1024*1024;
				}
				else {
					bytesToWrite = (ULONG) (Length - totalWritten );
				}

				if( bytesToWrite > CLEANBUFSIZE )
				{
					bytesToWrite = CLEANBUFSIZE;
				}

				if(!WriteFile( FileHandle, cleanBuffer[i], bytesToWrite, &bytesWritten, NULL))
				{
					return false;
				}

				// Note: no need to flush since the file is opened with write-through or 
				// no cache buffering

				totalWritten += bytesWritten;
			}
		}
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// SecureDelete
//
// Performs a secure delete on the specified file.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDelete(const char *sFileName, long FileLengthHi, unsigned long FileLengthLo, DWORD dwNumPasses)
{
	HANDLE	hFile;
	ULONGLONG bytesToWrite, bytesWritten;
	ULARGE_INTEGER fileLength;
	char sLastFileName[MAX_PATH];

	hFile = CreateFile(sFileName, GENERIC_WRITE, 
						FILE_SHARE_READ|FILE_SHARE_WRITE,
						NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL );

	if( hFile == INVALID_HANDLE_VALUE )
	{
		printf( "\nError opening %s for delete: ", sFileName );
		PrintWin32Error( GetLastError());
		return false;
	}

	if( FileLengthLo || FileLengthHi )
	{
		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

		fileLength.LowPart = FileLengthLo;
		fileLength.HighPart = FileLengthHi;

		bytesWritten = 0;

		while( bytesWritten < fileLength.QuadPart )
		{
			bytesToWrite = min( fileLength.QuadPart - bytesWritten, 65536 );
			if( !SecureOverwrite( hFile, (DWORD) bytesToWrite, dwNumPasses))
			{
				printf( "\nError overwriting %s: ", sFileName);
				PrintWin32Error( GetLastError() );
				CloseHandle( hFile );
				return false;
			}
			bytesWritten += bytesToWrite;
		}
	}

	// Done!
	CloseHandle( hFile );
	
	// Rename the file a few times
	OverwriteFileName(sFileName, sLastFileName );

	// Now we can delete the file
	if(!DeleteFile(sLastFileName))
	{
		printf( "\nError deleting %s: ", sFileName );
		PrintWin32Error( GetLastError() );

		// Rename back to original name so as not to confuse the user
		if( !MoveFile( sLastFileName, sFileName ))
		{
			printf("\nError renaming file back to original name. File is left as %s\n", sLastFileName);
		}
		return false;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// ScanFile
//
// This is only invoked for compressed, encrypted or sparse files, 
// which exists only on NTFS drives (WinNT/2K). Thus, we can use
// the defrag API to zap the clusters belonging to the file 
// Determines if the the file is non-resident (outside the MFT), and 
// if so and we were able to open the volume for write access, we zap 
// the clusters.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool ScanFile(HANDLE VolumeHandle, DWORD ClusterSize, HANDLE FileHandle, bool *ReallyCompressed, bool *ZappedFile, DWORD dwNumPasses)
{
	DWORD						status;
	int							i;
	IO_STATUS_BLOCK				ioStatus;
	ULONGLONG					startVcn, prevVcn;
	LARGE_INTEGER				clusterOffset;
	ULONGLONG					endOfPrevRun;
	PGET_RETRIEVAL_DESCRIPTOR	fileMappings;
	ULONGLONG					fileMap[ FILEMAPSIZE ];
	int							lines = 0;

	//
	// Assume file is in an MFT record.
	//
	*ReallyCompressed = false;
	*ZappedFile = false;

	startVcn = 0;
	endOfPrevRun = LLINVALID;
	fileMappings = (PGET_RETRIEVAL_DESCRIPTOR) fileMap;
	while( !(status = NtFsControlFile( FileHandle, NULL, NULL, 0, &ioStatus,
						FSCTL_GET_RETRIEVAL_POINTERS,
						&startVcn, sizeof(startVcn),
						fileMappings, FILEMAPSIZE * sizeof(ULONGLONG) ) ) ||
			 status == STATUS_BUFFER_OVERFLOW ||
			 status == STATUS_PENDING )
	{
		// If the operation is pending, wait for it to finish
		if( status == STATUS_PENDING )
		{
			WaitForSingleObject(FileHandle, INFINITE); 

			// Get the status from the status block
			if(ioStatus.Status != STATUS_SUCCESS && ioStatus.Status != STATUS_BUFFER_OVERFLOW)
			{
				return ioStatus.Status == STATUS_SUCCESS;
			}
		}

		// Loop through the buffer of number/cluster pairs, printing them out.
		startVcn = fileMappings->StartVcn;
		prevVcn  = fileMappings->StartVcn;
		for( i = 0; i < (ULONGLONG) fileMappings->NumberOfPairs; i++ )
		{	 
			// On NT 4.0, a compressed virtual run (0-filled) is identified with a cluster offset of -1
			if( fileMappings->Pair[i].Lcn != LLINVALID )
			{
				// Its compressed and outside the zone
				*ReallyCompressed = true;

				// Overwrite the clusters if we were able to open the volume for write access.
				if( VolumeHandle != INVALID_HANDLE_VALUE )
				{
					clusterOffset.QuadPart = fileMappings->Pair[i].Lcn * ClusterSize;
					SetFilePointer(VolumeHandle, clusterOffset.LowPart, &clusterOffset.HighPart, FILE_BEGIN);
					if(!SecureOverwrite( VolumeHandle, ClusterSize * (DWORD) (fileMappings->Pair[i].Vcn - startVcn), dwNumPasses))
					{
						// Couldn't zap the clusters, so we'll have to clean the free space
						return true;
					}							
				}
				else {
					return true;	
				}
			}
			startVcn = fileMappings->Pair[i].Vcn;
		}

		// If the buffer wasn't overflowed, then we're done
		if( !status )
		{
			break;
		}
	}

	// Return now if there were any errors
	if( status && status != STATUS_INVALID_PARAMETER )
	{
		printf("Scanning file: ");
		PrintNtError( status );
	}

	// If we made through with no errors we've overwritten all the file's clusters.
	if( status == STATUS_SUCCESS )
	{
		*ZappedFile = true;
	}

	return status == STATUS_SUCCESS;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// SecureDeleteCompressed
//
// More complicated than a regular file - we actually try to use
// direct disk access to overwrite the clusters that are used by a 
// compressed file. The function returns false if the file is
// not really compressed (it is stored as resident data in the MFT).
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDeleteCompressed(const char *sFileName, DWORD dwNumPasses)
{
	HANDLE hFile = NULL;
	bool nReallyCompressed = false;
	bool bZappedFile = false;
	char sLastFileName[MAX_PATH];
	static TCHAR	volumeName[] = "\\\\.\\A:";
	static TCHAR	volumeRoot[] = "A:\\";
	static HANDLE	hVolume = INVALID_HANDLE_VALUE;
	static DWORD	clusterSize;
	DWORD			sectorsPerCluster, bytesPerSector, freeClusters, totalClusters;

	// If we haven't opened the volume, attempt it now
	if( hVolume == INVALID_HANDLE_VALUE )
	{
		volumeName[4] = sFileName[0];
		hVolume = CreateFile( volumeName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0 );

		volumeRoot[0] = sFileName[0];
		GetDiskFreeSpace(volumeRoot, &sectorsPerCluster, &bytesPerSector, &freeClusters, &totalClusters);

		clusterSize = bytesPerSector * sectorsPerCluster;
	}

	//
	// Open the file exclusively
	//
	hFile = CreateFile( sFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if( hFile == INVALID_HANDLE_VALUE )
	{
		printf( "\nError opening %s for compressed file scan: ", sFileName);
		PrintWin32Error( GetLastError());
		return true;
	}
	
	//
	// Scan the location of the file
	//
	if(!ScanFile( hVolume, clusterSize, hFile, &nReallyCompressed, &bZappedFile, dwNumPasses))
	{
		CloseHandle( hFile );
		return true;
	}

	// Done with the file handle
	CloseHandle(hFile);

	// If the file is really compressed (it is non-resident),
	// we can delete it now.
	if(nReallyCompressed)
	{
		// Rename the file a few times
		OverwriteFileName(sFileName, sLastFileName);

		if(!DeleteFile(sLastFileName))
		{
			// Rename back to the original name on error so as not to confuse the user.
			printf("\nError deleting %s: ", sFileName);
			PrintWin32Error( GetLastError() );
			if(!MoveFile(sLastFileName, sFileName))
			{
				printf("\nError renaming file back to original name. File is left as %s\n", sLastFileName );
			}
			return true;
		}
	}

	// Return true if the file had clusters outside the MFT
	return nReallyCompressed;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// SecureDeleteFile
//
// Performs a secure delete on the specified file.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDeleteFile(const char *sFileName, DWORD dwNumPasses)
{
	if(bSecureDeleteSupported && dwNumPasses > 0)
	{
		SetFileAttributes(sFileName, FILE_ATTRIBUTE_NORMAL);

		DWORD dwFileAttributes = GetFileAttributes(sFileName);

		if((dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (dwFileAttributes == 0xFFFFFFFF))
		{
			//FIXFIX: handle error.
			return false;
		}

		// If the file is compressed, we have to go a different path
		if( dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED ||
			//dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED  ||
			dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE )
		{
			// We need to determine where the compressed file is located physically on disk.
			if( SecureDeleteCompressed(sFileName, dwNumPasses))
			{
				return true;
			}
		}

		HANDLE hfSource = CreateFile(sFileName, 0, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if(hfSource == INVALID_HANDLE_VALUE)
		{
			//FIXFIX: handle error.
			return false;
		}

		DWORD nFileSizeHigh = 0;
		DWORD nFileSizeLow = GetFileSize(hfSource, &nFileSizeHigh);

		if(nFileSizeLow == 0xFFFFFFFF && (GetLastError() != NO_ERROR))
		{
			CloseHandle(hfSource);
			//FIXFIX: handle error.
			return false;
		}

		CloseHandle(hfSource);

		// Regular path, non-compressed/encrypted/sparse file or one of those
		// types of files with their data resident in an MFT record: perform a 
		// simple secure delete.
		return SecureDelete(sFileName, nFileSizeHigh, nFileSizeLow, dwNumPasses);
	}
	else{
		SetFileAttributes(sFileName, FILE_ATTRIBUTE_NORMAL);
		return(DeleteFile(sFileName) != 0);
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// InitSecureDelete
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool InitSecureDelete(void)
{
	bSecureDeleteSupported = false;

	// If we're on Win9x, just return
	if(IsWindowsXPOrGreater() == FALSE)
	{
		return false;
	}

    // Load the NTDLL entry point we need
	if(!(NtFsControlFile = (NTSTATUS (__stdcall *)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,ULONG,PVOID,ULONG,PVOID,ULONG))
		GetProcAddress( GetModuleHandle("ntdll.dll"),"NtFsControlFile")))
	{
		printf("\nCould not find NtFsControlFile entry point in NTDLL.DLL\n");
		return false;
	}

	if(!(RtlNtStatusToDosError = (ULONG (__stdcall *)(NTSTATUS)) GetProcAddress( GetModuleHandle("ntdll.dll"), "RtlNtStatusToDosError")))
	{
		printf("\nCould not find RtlNtStatusToDosError entry point in NTDLL.DLL\n");
		return false;
	}

	bSecureDeleteSupported = true;

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
