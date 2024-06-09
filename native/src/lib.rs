use std::cell::RefCell;
use std::ffi::OsStr;
use std::io;
use std::mem::{self, offset_of};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};

use anyhow::{anyhow, Context as AnyhowContext, Result};
use neon::context::Context;
use neon::prelude::*;
use ntapi::ntmmapi::{NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection, ViewUnmap};
use shellcode::build_injected_code;
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::{LARGE_INTEGER, MAXULONG, NT_SUCCESS, OBJECT_ATTRIBUTES};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{
    ReadProcessMemory, VirtualProtectEx, VirtualQueryEx, WriteProcessMemory,
};
use winapi::um::processthreadsapi::{
    CreateProcessW, GetCurrentProcess, GetExitCodeProcess, ResumeThread, TerminateProcess,
    PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO};
use winapi::um::winbase::{CREATE_SUSPENDED, INFINITE};
use winapi::um::winnt::{
    HANDLE, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_DLL,
    IMAGE_FILE_HEADER, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, IMAGE_NT_HEADERS,
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, IMAGE_TLS_DIRECTORY32,
    IMAGE_TLS_DIRECTORY64, MEMORY_BASIC_INFORMATION, MEM_FREE, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PVOID, SECTION_MAP_EXECUTE, SECTION_MAP_READ,
    SECTION_MAP_WRITE, SECTION_QUERY, SEC_COMMIT, SEC_IMAGE,
};

mod shellcode;

macro_rules! log {
    ($($args:tt)*) => {{
        LOG_CALLBACK.with(|cb| {
            let cb = cb.borrow();
            if let Some(ref cb) = *cb {
                cb.log(format!($($args)*));
            }
        });
    }};
}

thread_local!(static LOG_CALLBACK: RefCell<Option<LogCallback>> = RefCell::new(None));

struct LogCallback {
    channel: Channel,
    callback: Arc<Option<Root<JsFunction>>>,
}

impl LogCallback {
    fn log(&self, msg: String) {
        let cb = self.callback.clone();
        let _ = self.channel.try_send(move |mut cx| {
            if let Some(ref cb) = *cb {
                let cb = cb.to_inner(&mut cx);
                cb.call_with(&cx).arg(cx.string(&msg)).exec(&mut cx)?;
            }
            Ok(())
        });
    }
}

impl Drop for LogCallback {
    fn drop(&mut self) {
        // Awkwardly we need to consume Root in order to properly drop it (And properly dropping it
        // is recommended in neon docs), but some of log callbacks may still be executing and we
        // can't immediately get unique access to it.
        // Try to wait for up to 5 seconds before giving up; neon is supposed to be able to clean
        // leaks itself too, so it should be fine to leak in the end.
        // And as long as LogCallback is just stored in TLS value, stalling for 5 seconds on thread
        // end should not matter for anyone..
        for i in 0..6 {
            if let Some(cb) = Arc::get_mut(&mut self.callback) {
                if let Some(inner) = cb.take() {
                    let _ = self.channel.try_send(|mut cx| {
                        inner.drop(&mut cx);
                        Ok(())
                    });
                }
            }
            if i != 5 {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        }
    }
}

fn system_info() -> &'static SYSTEM_INFO {
    static INIT: Once = Once::new();
    static mut INFO: mem::MaybeUninit<SYSTEM_INFO> = mem::MaybeUninit::uninit();

    unsafe {
        INIT.call_once(|| GetNativeSystemInfo(INFO.as_mut_ptr()));
        &*INFO.as_ptr()
    }
}

fn page_size() -> usize {
    system_info().dwPageSize as usize
}

fn allocation_granularity() -> usize {
    system_info().dwAllocationGranularity as usize
}

fn round_to_pages(s: usize) -> usize {
    s.saturating_add(page_size() - 1) & !(page_size() - 1)
}

fn align_down_by(s: usize, alignment: usize) -> usize {
    s & !(alignment - 1)
}

fn align_up_by(s: usize, alignment: usize) -> usize {
    align_down_by(s.saturating_add(alignment - 1), alignment)
}

pub trait PeTLS {
    fn addr_of_callbacks(&self) -> usize;
}

impl PeTLS for IMAGE_TLS_DIRECTORY64 {
    fn addr_of_callbacks(&self) -> usize {
        self.AddressOfCallBacks as usize
    }
}

impl PeTLS for IMAGE_TLS_DIRECTORY32 {
    fn addr_of_callbacks(&self) -> usize {
        self.AddressOfCallBacks as usize
    }
}

pub trait PeImage {
    fn imagebase(&self) -> usize;
    fn is_dll(&self) -> bool;
    fn valid_signature(&self) -> bool;
    fn machine(&self) -> u16;
    fn is64bit(&self) -> bool {
        self.machine() == IMAGE_FILE_MACHINE_AMD64
    }
    fn data_dir(&self, index: u16) -> IMAGE_DATA_DIRECTORY;
    fn export_dir(&self) -> IMAGE_DATA_DIRECTORY {
        self.data_dir(IMAGE_DIRECTORY_ENTRY_EXPORT)
    }
    fn export_dd(&self) -> Option<IMAGE_DATA_DIRECTORY> {
        let export_dd = self.export_dir();
        if export_dd.Size == 0
            || export_dd.VirtualAddress == 0
            || (export_dd.Size as usize) < mem::size_of::<IMAGE_EXPORT_DIRECTORY>()
        {
            return None;
        }
        Some(export_dd)
    }
    fn tls_dir(&self) -> IMAGE_DATA_DIRECTORY {
        self.data_dir(IMAGE_DIRECTORY_ENTRY_TLS)
    }
    fn tls_dd(&self) -> Option<IMAGE_DATA_DIRECTORY> {
        let tls_dd = self.tls_dir();
        if tls_dd.Size == 0 || tls_dd.VirtualAddress == 0 {
            return None;
        }

        match self.is64bit() {
            true if tls_dd.Size as usize == mem::size_of::<IMAGE_TLS_DIRECTORY64>() => Some(tls_dd),
            false if tls_dd.Size as usize == mem::size_of::<IMAGE_TLS_DIRECTORY32>() => {
                Some(tls_dd)
            }
            _ => None,
        }
    }
}

impl PeImage for IMAGE_NT_HEADERS32 {
    fn imagebase(&self) -> usize {
        self.OptionalHeader.ImageBase as usize
    }
    fn data_dir(&self, index: u16) -> IMAGE_DATA_DIRECTORY {
        if self.OptionalHeader.NumberOfRvaAndSizes <= index.into() {
            return IMAGE_DATA_DIRECTORY {
                VirtualAddress: 0,
                Size: 0,
            };
        }
        self.OptionalHeader.DataDirectory[index as usize]
    }
    fn is_dll(&self) -> bool {
        self.FileHeader.Characteristics & IMAGE_FILE_DLL != 0
    }
    fn valid_signature(&self) -> bool {
        self.Signature == IMAGE_NT_SIGNATURE
    }
    fn machine(&self) -> u16 {
        self.FileHeader.Machine as u16
    }
}

impl PeImage for IMAGE_NT_HEADERS64 {
    fn imagebase(&self) -> usize {
        self.OptionalHeader.ImageBase as usize
    }
    fn data_dir(&self, index: u16) -> IMAGE_DATA_DIRECTORY {
        if self.OptionalHeader.NumberOfRvaAndSizes <= index.into() {
            return IMAGE_DATA_DIRECTORY {
                VirtualAddress: 0,
                Size: 0,
            };
        }
        self.OptionalHeader.DataDirectory[index as usize]
    }
    fn is_dll(&self) -> bool {
        self.FileHeader.Characteristics & IMAGE_FILE_DLL != 0
    }
    fn valid_signature(&self) -> bool {
        self.Signature == IMAGE_NT_SIGNATURE
    }
    fn machine(&self) -> u16 {
        self.FileHeader.Machine as u16
    }
}

pub struct DynamicCodeSection {
    h: HANDLE,
    data_size: usize,
    view_size: usize,
}

impl DynamicCodeSection {
    pub fn new(data: &[u8]) -> Option<Self> {
        if data.len() > MAXULONG as usize {
            log!("Unsupported section size {}", data.len());
            return None;
        }

        let mut sect = Self {
            h: ptr::null_mut(),
            data_size: data.len(),
            view_size: 0,
        };

        unsafe {
            // Set the unnamed object attributes
            let mut obj_attr = OBJECT_ATTRIBUTES {
                Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                ..mem::zeroed()
            };

            // Create the section object
            let mut section_max_size: LARGE_INTEGER = std::mem::zeroed();
            section_max_size.u_mut().LowPart = round_to_pages(data.len()) as u32;
            let status = NtCreateSection(
                ptr::addr_of_mut!(sect.h),
                SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY | SECTION_MAP_EXECUTE,
                ptr::addr_of_mut!(obj_attr),
                ptr::addr_of_mut!(section_max_size),
                PAGE_EXECUTE_READWRITE,
                SEC_COMMIT,
                ptr::null_mut(),
            );
            if !NT_SUCCESS(status) {
                log!("Failed creating DynamicCodeSection");
                return None;
            }

            // Map it with write permissions so we can write to it
            let mut section_offset: LARGE_INTEGER = std::mem::zeroed();
            let mut view_size: usize = 0;
            let mut map_base: PVOID = ptr::null_mut();
            let status = NtMapViewOfSection(
                sect.h,
                GetCurrentProcess(),
                ptr::addr_of_mut!(map_base),
                0,
                data.len(),
                ptr::addr_of_mut!(section_offset),
                ptr::addr_of_mut!(view_size),
                ViewUnmap,
                0,
                PAGE_READWRITE,
            );
            if !NT_SUCCESS(status) {
                log!("Failed to map DynamicCodeSection");
                return None;
            }

            if view_size < data.len() {
                log!("Section is too small");
                return None;
            }

            // Copy the input buffer
            let section_data = std::slice::from_raw_parts_mut(map_base as *mut u8, data.len());
            section_data.clone_from_slice(data);
            sect.view_size = view_size;

            // Unmap our data view
            NtUnmapViewOfSection(GetCurrentProcess(), map_base);
        }

        Some(sect)
    }

    pub fn handle(&self) -> HANDLE {
        self.h
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn view_size(&self) -> usize {
        self.data_size
    }
}

impl Drop for DynamicCodeSection {
    fn drop(&mut self) {
        unsafe {
            if !self.h.is_null() {
                CloseHandle(self.h);
            }
        }
    }
}

pub struct Process {
    h: HANDLE,
}

struct TerminateOnDrop<'a>(&'a Process);

impl<'a> Drop for TerminateOnDrop<'a> {
    fn drop(&mut self) {
        let ok = unsafe { TerminateProcess(self.0.handle(), 0) };
        if ok == 0 {
            log!(
                "Failed to terminate process {:p}: {}",
                self.0,
                io::Error::last_os_error()
            );
        }
    }
}

pub trait MemRegion {
    fn addr(&self) -> usize;
    fn size(&self) -> usize;
    fn end_addr(&self) -> usize {
        self.addr().saturating_add(self.size())
    }
    fn prot(&self) -> u32;

    fn is_image(&self) -> bool;
    fn is_free(&self) -> bool;
}

impl MemRegion for MEMORY_BASIC_INFORMATION {
    fn addr(&self) -> usize {
        self.BaseAddress as usize
    }

    fn size(&self) -> usize {
        self.RegionSize
    }

    fn prot(&self) -> u32 {
        self.Protect
    }

    fn is_image(&self) -> bool {
        self.Type == SEC_IMAGE
    }

    fn is_free(&self) -> bool {
        self.State == MEM_FREE
    }
}

pub struct MemRegionIter<'a> {
    proc: &'a Process,
    curr_address: usize,
    end_address: usize,
}

impl<'a> MemRegionIter<'a> {
    pub fn new(proc: &'a Process) -> Self {
        let system = system_info();

        Self {
            proc,
            curr_address: 0,
            end_address: system.lpMaximumApplicationAddress as usize,
        }
    }
}

impl<'a> Iterator for MemRegionIter<'a> {
    type Item = MEMORY_BASIC_INFORMATION;
    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_address < self.end_address {
            let mbi = self.proc.virtual_query(self.curr_address)?;
            self.curr_address = mbi.end_addr();
            return Some(mbi);
        }

        None
    }
}

fn winapi_str(input: &str) -> Vec<u16> {
    OsStr::new(input)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>()
}

impl Process {
    pub fn new_from_path(path: &str, args: &str, current_dir: &str) -> Result<(Self, HANDLE)> {
        unsafe {
            let mut process_info: PROCESS_INFORMATION = mem::zeroed();
            let mut startup_info = STARTUPINFOW {
                cb: mem::size_of::<STARTUPINFOW>() as u32,
                ..mem::zeroed()
            };

            let win_path = winapi_str(path);
            // CreateProcessW takes args by mutable pointer for whatever reason
            let mut win_args = winapi_str(args);
            let win_dir = winapi_str(current_dir);

            let success = CreateProcessW(
                win_path.as_ptr(),
                win_args.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                FALSE,
                CREATE_SUSPENDED,
                ptr::null_mut(),
                win_dir.as_ptr(),
                &mut startup_info,
                &mut process_info,
            );

            if success == FALSE {
                return Err(anyhow!(
                    "Failed to create process {}: {}",
                    path,
                    io::Error::last_os_error()
                ));
            }

            Ok((
                Self {
                    h: process_info.hProcess,
                },
                process_info.hThread,
            ))
        }
    }

    pub fn handle(&self) -> HANDLE {
        self.h
    }

    pub fn wait(&self, milliseconds: u32) {
        unsafe {
            WaitForSingleObject(self.h, milliseconds);
        }
    }

    pub fn exit_code(&self) -> Result<u32> {
        unsafe {
            let mut code = 0;
            let ok = GetExitCodeProcess(self.h, &mut code);
            if ok == 0 {
                Err(io::Error::last_os_error().into())
            } else {
                Ok(code)
            }
        }
    }

    pub fn virtual_query(&self, addr: usize) -> Option<MEMORY_BASIC_INFORMATION> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let bytes = VirtualQueryEx(self.h, addr as PVOID, &mut mbi, mem::size_of_val(&mbi));

            if bytes == 0 {
                return None;
            }

            Some(mbi)
        }
    }

    pub fn read(&self, addr: usize, length: usize) -> Option<Vec<u8>> {
        let mut buffer: Vec<u8> = vec![0u8; length];

        unsafe {
            if ReadProcessMemory(
                self.h,
                addr as PVOID,
                buffer.as_mut_ptr() as PVOID,
                length,
                ptr::null_mut(),
            ) == FALSE
            {
                log!(
                    "ReadProcessMemory({:x?} Len:{:x?}) failed GLE:{}",
                    addr,
                    length,
                    GetLastError()
                );
                return None;
            }
        }

        Some(buffer)
    }

    pub fn read_struct<T: Sized>(&self, addr: usize, obj: *mut T) -> Option<()> {
        unsafe {
            if ReadProcessMemory(
                self.h,
                addr as PVOID,
                obj as PVOID,
                mem::size_of::<T>(),
                ptr::null_mut(),
            ) == FALSE
            {
                log!(
                    "ReadProcessMemory({:x?} Len:{:x?}) failed GLE:{}",
                    addr,
                    mem::size_of::<T>(),
                    GetLastError()
                );
                return None;
            }
        }

        Some(())
    }

    pub fn write(&self, addr: usize, data: &[u8]) -> Option<usize> {
        unsafe {
            let mut written = 0usize;
            if WriteProcessMemory(
                self.h,
                addr as PVOID,
                data.as_ptr() as PVOID,
                data.len(),
                &mut written,
            ) == FALSE
            {
                return None;
            }

            Some(written)
        }
    }

    pub fn protect(&self, addr: usize, length: usize, prot: u32) -> Option<u32> {
        unsafe {
            let mut old_prot = 0u32;
            if VirtualProtectEx(self.h, addr as PVOID, length, prot, &mut old_prot) == FALSE {
                return None;
            }

            Some(old_prot)
        }
    }

    pub fn map_entire_section(
        &self,
        section: &DynamicCodeSection,
        min_start_addr: Option<usize>,
        prot: u32,
    ) -> Option<usize> {
        self.iter_free_regions().find_map(|m| {
            // Make sure we have enough room
            if m.size() < section.view_size() {
                return None;
            }

            // If the user request to be after an address
            if let Some(min_start) = min_start_addr {
                if m.addr() < min_start {
                    return None;
                }
            }

            let mut dest_addr: usize = m.addr();
            if m.addr() & (allocation_granularity() - 1) != 0 {
                // See if we can find a slice
                dest_addr = align_up_by(m.addr(), allocation_granularity());
                let delta = dest_addr - m.addr();
                if delta > m.size() {
                    return None;
                }

                if section.view_size() > m.size() - delta {
                    return None;
                }
            }

            unsafe {
                let mut view_size: usize = section.view_size();
                let mut section_offset: LARGE_INTEGER = std::mem::zeroed();
                let status = NtMapViewOfSection(
                    section.handle(),
                    self.h,
                    ptr::addr_of_mut!(dest_addr) as *mut PVOID,
                    0,
                    section.view_size(),
                    ptr::addr_of_mut!(section_offset),
                    ptr::addr_of_mut!(view_size),
                    ViewUnmap,
                    0,
                    prot,
                );
                if !NT_SUCCESS(status) {
                    return None;
                }
            }

            Some(dest_addr)
        })
    }

    pub fn iter_regions(&self) -> MemRegionIter {
        MemRegionIter::new(self)
    }

    pub fn iter_free_regions(&self) -> impl Iterator<Item = MEMORY_BASIC_INFORMATION> + '_ {
        MemRegionIter::new(self).filter(|m| m.is_free())
    }

    fn read_image_header<T: MemRegion>(&self, region: &T) -> Option<Box<dyn PeImage>> {
        // Read the DOS header
        let mut dos_hdr: IMAGE_DOS_HEADER = unsafe { mem::zeroed() };
        self.read_struct(region.addr(), ptr::addr_of_mut!(dos_hdr))?;
        if dos_hdr.e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }

        // Read the FileHeader header
        let nt_header_addr = region.addr() + dos_hdr.e_lfanew as usize;
        let file_header_addr = nt_header_addr + offset_of!(IMAGE_NT_HEADERS, FileHeader);
        let mut file_header: IMAGE_FILE_HEADER = unsafe { mem::zeroed() };
        self.read_struct(file_header_addr, ptr::addr_of_mut!(file_header))?;

        // Get the appropriate NT header structure
        let nt_header_data = self.read(
            nt_header_addr,
            match file_header.Machine {
                IMAGE_FILE_MACHINE_AMD64 => mem::size_of::<IMAGE_NT_HEADERS64>(),
                IMAGE_FILE_MACHINE_I386 => mem::size_of::<IMAGE_NT_HEADERS32>(),
                _ => return None,
            },
        )?;

        let nt_header: Box<dyn PeImage> = match file_header.Machine {
            IMAGE_FILE_MACHINE_AMD64 => unsafe {
                Box::new(mem::transmute_copy::<
                    [u8; mem::size_of::<IMAGE_NT_HEADERS64>()],
                    IMAGE_NT_HEADERS64,
                >(&nt_header_data[..].try_into().ok()?))
            },
            IMAGE_FILE_MACHINE_I386 => unsafe {
                Box::new(mem::transmute_copy::<
                    [u8; mem::size_of::<IMAGE_NT_HEADERS32>()],
                    IMAGE_NT_HEADERS32,
                >(&nt_header_data[..].try_into().ok()?))
            },
            _ => return None,
        };

        if !nt_header.valid_signature() {
            return None;
        }

        Some(nt_header)
    }

    pub fn iter_images<'a>(
        &'a self,
    ) -> impl Iterator<Item = (MEMORY_BASIC_INFORMATION, Box<dyn PeImage + 'static>)> + 'a {
        self.iter_regions().filter_map(|m| {
            if !m.is_image() {
                return None;
            }

            self.read_image_header(&m).map(|img| (m, img))
        })
    }
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            if !self.h.is_null() {
                CloseHandle(self.h);
            }
        }
    }
}

impl Finalize for Process {
    fn finalize<'a, C: Context<'a>>(self, _: &mut C) {
        // No JS cleanup needed.
    }
}

fn find_ntdll(proc: &Process, machine: u16) -> Option<usize> {
    proc.iter_images().find_map(|(m, img)| {
        if !img.is_dll() || img.machine() != machine {
            return None;
        }

        let exp_dd = img.export_dd()?;
        let mut exp_dir: IMAGE_EXPORT_DIRECTORY = unsafe { mem::zeroed() };
        proc.read_struct(
            m.addr() + exp_dd.VirtualAddress as usize,
            ptr::addr_of_mut!(exp_dir),
        )?;

        let exp_name_addr = m.addr() + exp_dir.Name as usize;
        match proc.read(exp_name_addr, "ntdll.dll\0".len()) {
            Some(name) if name.eq_ignore_ascii_case(b"ntdll.dll\0") => Some(m.addr()),
            _ => None,
        }
    })
}

fn find_exe(proc: &Process) -> Option<(usize, Box<dyn PeImage>)> {
    proc.iter_images().find_map(|(m, img)| {
        if img.is_dll() {
            return None;
        }
        Some((m.addr(), img))
    })
}

fn read_img_tls<T: PeImage + ?Sized>(
    proc: &Process,
    img_base: usize,
    img: &T,
) -> Option<Box<dyn PeTLS>> {
    let tls_dd = img.tls_dd()?;
    let tls_data = proc.read(
        img_base + tls_dd.VirtualAddress as usize,
        tls_dd.Size as usize,
    )?;
    match img.is64bit() {
        true => unsafe {
            Some(Box::new(mem::transmute_copy::<
                [u8; mem::size_of::<IMAGE_TLS_DIRECTORY64>()],
                IMAGE_TLS_DIRECTORY64,
            >(&tls_data[..].try_into().ok()?)))
        },
        false => unsafe {
            Some(Box::new(mem::transmute_copy::<
                [u8; mem::size_of::<IMAGE_TLS_DIRECTORY32>()],
                IMAGE_TLS_DIRECTORY32,
            >(&tls_data[..].try_into().ok()?)))
        },
    }
}

fn read_proc_pointer<T: PeImage + ?Sized>(proc: &Process, addr: usize, img: &T) -> Option<usize> {
    match img.is64bit() {
        true => {
            let data = proc.read(addr, mem::size_of::<u64>())?;
            if data.len() != mem::size_of::<u64>() {
                return None;
            }
            Some(u64::from_le_bytes(data.try_into().unwrap()) as usize)
        }
        false => {
            let data = proc.read(addr, mem::size_of::<u32>())?;
            if data.len() != mem::size_of::<u32>() {
                return None;
            }
            Some(u32::from_le_bytes(data.try_into().unwrap()) as usize)
        }
    }
}

fn write_proc_pointer<T: PeImage + ?Sized>(
    proc: &Process,
    addr: usize,
    value: usize,
    img: &T,
) -> Option<usize> {
    match img.is64bit() {
        true => proc.write(addr, &(value as u64).to_le_bytes()),
        false => proc.write(addr, &(value as u32).to_le_bytes()),
    }
}

fn start_injected(
    exe_path: &str,
    args: &str,
    current_dir: &str,
    dll_path: &str,
    func_name: &str,
) -> Result<Process> {
    // Start the new process
    let (proc, main_thread) =
        Process::new_from_path(exe_path, args, current_dir).context("Failed to create process")?;
    log!("Process created");
    let terminate_on_err = TerminateOnDrop(&proc);

    // Locate the exe image
    let (exe_base, exe_img) = find_exe(&proc).context("Failed to locate EXE image")?;

    // Locate the corresponding NTDLL
    let ntdll_base =
        find_ntdll(&proc, exe_img.machine()).context("Failed to locate NTDLL image")?;

    // Get the EXE image TLS
    log!("Locating first TLS callback..");
    let exe_tls =
        read_img_tls(&proc, exe_base, exe_img.as_ref()).context("Failed reading Exe TLS")?;
    let tls_first_cb = read_proc_pointer(&proc, exe_tls.addr_of_callbacks(), exe_img.as_ref())
        .context("Failed reading Exe first TLS callback")?;
    // Relocate the callback
    let tls_first_cb = tls_first_cb - exe_img.imagebase() + exe_base;
    log!("First TLS CB found");

    // Build the inject shellcode
    let injected_code = DynamicCodeSection::new(
        &build_injected_code(
            exe_img.is64bit(),
            ntdll_base,
            tls_first_cb,
            dll_path,
            func_name,
        )[..],
    )
    .context("Failed to build DynamicCodeSection")?;

    // Insert our shellcode to the process
    let injected_code_base = proc
        .map_entire_section(&injected_code, Some(exe_base), PAGE_EXECUTE_READWRITE)
        .context("Failed to map section")?;
    log!("Shellcode mapped into process");

    // Patch the TLS first callback to point to our shellcode
    let _ = proc
        .protect(
            exe_tls.addr_of_callbacks(),
            match exe_img.is64bit() {
                true => mem::size_of::<u64>(),
                false => mem::size_of::<u32>(),
            },
            PAGE_EXECUTE_WRITECOPY,
        )
        .context("Failed to protect Tls Callback Array")?;
    let _ = write_proc_pointer(
        &proc,
        exe_tls.addr_of_callbacks(),
        injected_code_base,
        exe_img.as_ref(),
    )
    .context("Failed to patch Tls callback entry")?;
    log!("TLS callback patched, resuming process..");

    // Resume the process
    unsafe {
        ResumeThread(main_thread);
    }

    mem::forget(terminate_on_err);
    Ok(proc)
}

/// Just a failsafe to prevent too many threads from being spawned and leaked.
static INJECT_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

struct DecrementInjectThreadCount;

impl Drop for DecrementInjectThreadCount {
    fn drop(&mut self) {
        INJECT_THREAD_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

fn launch(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let cx = &mut cx;
    let channel = cx.channel();
    let params = cx.argument::<JsObject>(0)?;
    let mut get_string = |name| Ok(params.get::<JsString, _, _>(cx, name)?.value(cx));
    let path = get_string("appPath")?;
    let args = get_string("args")?;
    let current_dir = get_string("currentDir")?;
    let dll_path = get_string("dllPath")?;
    let func = get_string("dllFunc")?;

    let log_callback = params.get::<JsFunction, _, _>(cx, "logCallback")?;
    let log_callback = log_callback.root(cx);
    let log_callback = LogCallback {
        channel: channel.clone(),
        callback: Arc::new(Some(log_callback)),
    };

    let (deferred, promise) = cx.promise();
    if INJECT_THREAD_COUNT.load(Ordering::Relaxed) > 10 {
        // ???? Something is not working, but not sure what we can do.
        // So just throw an error and don't create more threads as long as the existing
        // ones are still running. Hopefully they exit at some point.
        return cx.throw_error("Inject thread limit reached");
    }
    std::thread::spawn(move || {
        LOG_CALLBACK.with(|cb| {
            *cb.borrow_mut() = Some(log_callback);
        });
        INJECT_THREAD_COUNT.fetch_add(1, Ordering::Relaxed);
        let _decrement_on_func_exit = DecrementInjectThreadCount;
        let result = std::panic::catch_unwind(|| {
            start_injected(&path, &args, &current_dir, &dll_path, &func)
        });
        let result = match result {
            Ok(res) => res,
            Err(panic) => {
                if let Some(msg) = panic.downcast_ref::<String>() {
                    Err(anyhow!("Inject thread panicked with message {}", msg))
                } else if let Some(msg) = panic.downcast_ref::<&'static str>() {
                    Err(anyhow!("Inject thread panicked with message {}", msg))
                } else {
                    Err(anyhow!("Inject thread panicked with unknown panic payload"))
                }
            }
        };
        let _ = deferred.try_settle_with(&channel, move |mut cx| match result {
            Ok(process) => Ok(cx.boxed(Arc::new(process))),
            Err(e) => {
                let msg = format!("{:?}", e);
                cx.throw_error(msg)
            }
        });
    });
    Ok(promise)
}

fn wait_for_exit(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let cx = &mut cx;
    let process = cx.argument::<JsBox<Arc<Process>>>(0)?;
    let process = Arc::clone(&process);
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();
    // Spawning a new thread for this is a bit silly, but let's assume there's not
    // going to be hundred different processes that are being waited on simultaneously.
    // A better solution would use/integrate with something that uses WaitForMultipleObjects.
    std::thread::spawn(move || {
        INJECT_THREAD_COUNT.fetch_add(1, Ordering::Relaxed);
        let _decrement_on_func_exit = DecrementInjectThreadCount;
        process.wait(INFINITE);
        let result = process.exit_code();
        let _ = deferred.try_settle_with(&channel, move |mut cx| match result {
            Ok(exit_code) => Ok(cx.number(exit_code)),
            Err(e) => {
                let msg = format!("{:?}", e);
                cx.throw_error(msg)
            }
        });
    });
    Ok(promise)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("launch", launch)?;
    cx.export_function("waitForExit", wait_for_exit)?;
    Ok(())
}
