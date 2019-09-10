_core_schema = {
    'non_cooked_payload': {
        'metadata': {
            'file_name': '',
            'e_magic': '',
            'signature': '',
            'imphash': '',
            'executable_code_size': '',
            'executable_image_size': '',
        },
        'file_header': {
            'machine_type': '',
            'timedatestamp': '',
        },
        'image_optional_header64': {
            'magic': '',
            'major_linker_version': '',
            'minor_linker_version': '',
            'major_os_version': '',
            'minor_os_version': ''
        },
        'directory_entry_debug': [],
        'directory_entry_import': {}
    },
    'preflight_checks': {
        'rewrite': {
            'non_cooked_sha256': '',
            'cooked_sha256': '',
        },
        'preflight': False,
    },
    'cooked_payload': {
        'metadata': {
            'file_name': '',
            'md5': '',
            'sha1': '',
            'sha256': '',
            'sha512': '',
            'imphash': '',
            'ssdeep': '',
            'magic': '',
            'exif': {}
        }
    }
}

# This section can be broken down into a few destinct sections:
# 5: ALERT: Check your self
# 4: DANGER: This isnt a NOGO but should be removed if at all possible
# 3: WARNING: May be worth looking into
# 2: OK: Move forward
# 1: UNCLASSIFIED: Unkown submit a PR and c

_warn_level = {
    5: 'ALERT',
    4: 'DANGER',
    3: 'WARNING',
    2: 'OK',
    1: 'UNKNOWN'
}

_warn_color = {
    5: 'red',
    4: 'yellow',
    3: 'cyan',
    2: 'green',
    1: 'white'
}

_dirty_imports_model = {
    'KERNEL32.dll': {
        'CreateRemoteThread': {'status': 5, 'message': 'This import is often flagged for remote process injection.'},
        'GetCurrentProcess': {'status': 3, 'message': 'This import can be concerning, but only with other imports of concern.'},
        'IsDebuggerPresent': {'status': 5, 'message': 'Import offten flagged for sandbox / analysis evasion'},
        'RtlVirtualUnwind': {'status': 2, 'message': 'Exception handling'},
        'RtlLookupFunctionEntry': {'status': 2, 'message': 'Exception handling'},
        'RtlCaptureContext': {'status': 2, 'message': 'Exception handling'},
        'InitializeSListHead': {'status': 2, 'message': 'Compiler optimization'},
        'SetUnhandledExceptionFilter': {'status': 2, 'message': 'Exception handling'},
        'GetLastError': {'status': 2, 'message': 'Exception handling'},
        'UnhandledExceptionFilter': {'status': 2, 'message': 'Exception handling'},
        'VirtualAllocEx': {'status': 4, 'message': 'Import is often flagged for shellcode injection.'},
        'GetProcAddress': {'status': 4, 'message': 'Import is often flagged for shellcode injection.'},
        'CreateEventW': {'status': 2, 'message': 'Various OS interaction'},
        'TerminateProcess': {'status': 2, 'message': 'Various OS interaction'},
        'IsProcessorFeaturePresent': {'status': 3, 'message': 'This import can be concerning, but only with other imports of concern.'},
        'DeleteCriticalSection': {'status': 2, 'message': 'Various OS interaction'},
        # http://demin.ws/blog/russian/2009/03/05/queryperformancecounter-on-multicore-and-virtual-systems/
        'QueryPerformanceCounter': {'status': 4, 'message': 'Import offten flagged for sandbox / analysis evasion'},
        'GetCurrentProcessId': {'status': 3, 'message': 'This import can be concerning, but only with other imports of concern.'},
        'GetCurrentThreadId': {'status': 3, 'message': 'This import can be concerning, but only with other imports of concern.'},
        'ReadFile': {'status': 2, 'message': 'Various OS interaction'},
        'GetSystemTimeAsFileTime': {'status': 2, 'message': 'Various OS interaction'},
        'CreateProcessW': {'status': 5, 'message': 'This import is often flagged for remote process injection.'},
        'GetModuleHandleW': {'status': 4, 'message': 'Import offten flagged for dynamic function location'},
        'OpenProcess': {'status': 4, 'message': 'Import offten flagged for dynamic function location'},
        'WriteProcessMemory': {'status': 4, 'message': 'Import offten flagged for dynamic function location'},
        'CloseHandle': {'status': 2, 'message': 'Various OS interaction'},
        'EnterCriticalSection': {'status': 2, 'message': 'Exception handling'},
        'InitializeCriticalSection': {'status': 2, 'message': 'Exception handling'},
        'GetTickCount': {'status': 4, 'message': 'Import offten flagged for sandbox / analysis evasion'},
        'Sleep': {'status': 4, 'message': 'Import offten flagged for sandbox / analysis evasion'},
        'TlsGetValue': {'status': 2, 'message': 'Exception handling'},
        'ConnectNamedPipe': {'status': 3, 'message': 'This import can be concerning, but only with other imports of concern.'},
        'CreateNamedPipeA': {'status': 3, 'message': 'This import can be concerning, but only with other imports of concern.'},
        'CreateThread': {'status': 3, 'message': 'This import can be concerning, but only with other imports of concern.'},
        'CreateFileA': {'status': 2, 'message': 'Various OS interaction'},
    },
    'mscoree.dll': {
        '_CorExeMain': {'status':2, 'message': 'Managed executable entry for assemblies'}
    },
    'ADVAPI32.dll': {
        'AdjustTokenPrivileges': {'status': 4, 'message': 'Import used for token manipulation'},
        'OpenProcessToken': {'status': 3, 'message': 'Import used for token manipulation'},
        'LookupPrivilegeValueW': {'status': 3, 'message': 'Import used for token manipulation'},
    },
    'VCRUNTIME140.dll': {
        'memcpy': {'status': 2, 'message': 'Various OS interaction'},
        'memmove': {'status': 2, 'message': 'Various OS interaction'},
        '__std_terminate': {'status': 2, 'message': 'Various OS interaction'},
        '__std_exception_copy': {'status': 2, 'message': 'Various OS interaction'},
        '__std_exception_destroy': {'status': 2, 'message': 'Various OS interaction'},
        '_CxxThrowException': {'status': 2, 'message': 'Various OS interaction'},
        '__CxxFrameHandler3': {'status': 2, 'message': 'Various OS interaction'},
        'memset': {'status': 2, 'message': 'Various OS interaction'},
        '__C_specific_handler': {'status': 2, 'message': 'Various OS interaction'},
        '__vcrt_InitializeCriticalSectionEx': {'status': 2, 'message': 'Various OS interaction'},
    }
}




