use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
    winapi_local::um::winnt::{__readfsdword, __readgsqword},
};
use std::{ffi::CStr, mem, ptr};
use widestring::WideCString;
use winapi::{
    shared::{
        basetsd::DWORD_PTR,
        minwindef::{BYTE, DWORD, FARPROC, HMODULE, WORD},
        ntdef::{CHAR, LIST_ENTRY, PVOID, VOID},
    },
    um::winnt::{
        IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER,
        IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64,
    },
};

pub fn get_module_handle(module_name: &str) -> HMODULE {
    unsafe {
        let proc_env_block = if cfg!(target_arch = "x86") {
            __readfsdword(0x30) as *const PEB
        } else {
            __readgsqword(0x60) as *const PEB
        };

        if cfg!(debug_assertions) {
            println!("[*] Getting module handle for {}", module_name);
        }

        if module_name.as_ptr().is_null() {
            return (*proc_env_block).ImageBaseAddress as HMODULE;
        } else {
            let ldr = (*proc_env_block).Ldr;
            let module_list = &mut (*ldr).InMemoryOrderModuleList;
            let start_list_entry = (*module_list).Flink;

            let mut list_entry = start_list_entry;
            while list_entry != module_list {
                let entry = (list_entry as *mut u8).sub(mem::size_of::<LIST_ENTRY>())
                    as *const LDR_DATA_TABLE_ENTRY;
                let module_entry_name = WideCString::from_ptr_truncate(
                    (*entry).BaseDllName.Buffer,
                    (*entry).BaseDllName.Length as usize,
                );

                if module_name.to_lowercase() == module_entry_name.to_string_lossy().to_lowercase() {
                    if cfg!(debug_assertions) {
                        println!("\t[*] Found {} at {:p}", module_name, (*entry).DllBase);
                    }
                    return (*entry).DllBase as HMODULE;
                }

                list_entry = (*list_entry).Flink;
            }
            return ptr::null_mut() as HMODULE;
        }
    }
}

pub fn get_proc_address_by_name(handle_module: HMODULE, proc_name: &str) -> FARPROC {
    const DOS_HEADER_MAGIC: u16 = 0x5a4d;
    const NT_HEADERS_SIGNATURE: u32 = 0x4550;

    unsafe {
        if cfg!(debug_assertions) {
            println!("[*] Getting procedure address for {}", proc_name);
        }

        let base_address = handle_module as *const BYTE;

        let dos_header = base_address as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != DOS_HEADER_MAGIC {
            if cfg!(debug_assertions) {
                println!("\t[!] Invalid DOS header magic value");
            }
            return ptr::null_mut() as FARPROC;
        }

        let nt_headers =
            base_address.offset((*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != NT_HEADERS_SIGNATURE {
            if cfg!(debug_assertions) {
                println!("\t[!] Invalid NT headers signature value");
            }
            return ptr::null_mut() as FARPROC;
        }

        let optional_header = &(*nt_headers).OptionalHeader as *const IMAGE_OPTIONAL_HEADER64;
        let export_data_dir = &(*optional_header).DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            as *const IMAGE_DATA_DIRECTORY;
        let export_dir_address = base_address.offset((*export_data_dir).VirtualAddress as isize)
            as *const IMAGE_EXPORT_DIRECTORY;

        let eat =
            base_address.offset((*export_dir_address).AddressOfFunctions as isize) as *const DWORD;
        let func_name_table =
            base_address.offset((*export_dir_address).AddressOfNames as isize) as *const DWORD;
        let hints_table = base_address.offset((*export_dir_address).AddressOfNameOrdinals as isize)
            as *const WORD;

        let mut proc_address: PVOID = ptr::null_mut();

        // Resolve function by name! We're not dealing with redirectors. Be aware of it. :)

        for i in 0..(*export_dir_address).NumberOfNames {
            let tmp_func_name_table_offset = *(func_name_table.offset(i as isize));
            let tmp_func_name =
                base_address.offset(tmp_func_name_table_offset as isize) as *const CHAR;

            if proc_name == CStr::from_ptr(tmp_func_name).to_str().unwrap() {
                let hints_table_entry = *hints_table.offset(i as isize);
                let eat_entry = *eat.offset(hints_table_entry as isize) as DWORD_PTR;
                proc_address = base_address.offset(eat_entry as isize) as *mut VOID;
                if cfg!(debug_assertions) {
                    println!("\t[*] Found {} at {:p}", proc_name, proc_address);
                }
                break;
            }
        }
        proc_address as FARPROC
    }
}
