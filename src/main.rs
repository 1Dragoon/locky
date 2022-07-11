use clap::Parser;
use core::slice;

use rayon::{prelude::*, Scope};
use std::{
    collections::HashSet,
    fs::{self, DirEntry},
    io,
    os::windows::prelude::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::mpsc::{self, Sender},
};
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
use windows::Win32::{
    Foundation::{SetLastError, ERROR_SUCCESS, PWSTR, WIN32_ERROR},
    System::RestartManager::{
        RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY,
        RM_PROCESS_INFO,
    },
};

trait PathExt {
    fn dunce_canonicalize(&self) -> io::Result<PathBuf>;
}

impl PathExt for Path {
    fn dunce_canonicalize(&self) -> io::Result<PathBuf> {
        dunce::canonicalize(&self)
    }
}

#[derive(Debug, Parser)]
#[clap(name = "locky", about = "Who locked it?")]
struct Opt {
    /// Source directory
    source: String,
}

fn main() {
    let args = Opt::parse();
    let source = args.source;
    let (tx, rx) = mpsc::channel();
    rayon::scope(|s| scan(&source, tx, s));
    let received: (Vec<_>, Vec<_>) = rx.into_iter().unzip();
    let (file_set, sizes) = received;
    let file_count = file_set.len();
    let total_size: u64 = sizes.into_iter().sum();
    let paths = file_set
        .chunks(1024)
        .collect::<Vec<_>>()
        .par_iter()
        .flat_map(|f| {
            f.iter()
                .map(|f| f.as_ref().unwrap().path())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    println!("{file_count}, {total_size}");

    let pids = get_pids(&paths);
    println!("{:?}", pids);

    let mut pidshs = HashSet::new();
    pidshs.extend(pids);
    pidshs.iter().for_each(|f| {
        let sys = System::new_all();
        sys.process(Pid::from_u32(*f)).unwrap().kill();
    });
}

fn get_pids(paths: &[PathBuf]) -> Vec<u32> {
    paths
        .chunks(8192)
        .collect::<Vec<_>>()
        .par_iter()
        .flat_map(|f| {
            f.iter()
                .filter_map(|f| {
                    f // This should somehow warn if we can't read from something
                        .dunce_canonicalize()
                        .map(|g| g.as_os_str().encode_wide().chain([0]).collect::<Vec<u16>>())
                        .ok()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .chunks(128)
        .collect::<Vec<_>>()
        .par_iter()
        .filter_map(|f| match get_chunk_pids(f) {
            Ok(ok) => Some(ok),
            Err(err) => {
                println!("{err}");
                None
            }
        })
        .flatten()
        .collect::<Vec<u32>>()
}

fn get_chunk_pids(paths: &[Vec<u16>]) -> Result<Vec<u32>, String> {
    let paths_pwstr = paths.iter().map(|f| PWSTR(f.as_ptr())).collect::<Vec<_>>();
    let ppaths_pwstr = paths_pwstr.as_ptr();
    let max_return = paths.len() * 16;

    let mut key = vec![0; (CCH_RM_SESSION_KEY + 1).try_into().unwrap()];
    let strsessionkey = PWSTR(key.as_mut_ptr()); // example in C++ done as WCHAR szSessionKey[CCH_RM_SESSION_KEY+1] = { 0 };
    let mut dw_session = 0;
    let dwsessionflags = 0;

    let mut dw_error = unsafe { RmStartSession(&mut dw_session, dwsessionflags, strsessionkey) };

    if dw_error == ERROR_SUCCESS.0 {
        dw_error = unsafe {
            RmRegisterResources(
                dw_session,
                paths.len() as _,
                ppaths_pwstr,
                0, // Number of applications we expect?
                ptr::null(),
                0, // Number of services we expect?
                ptr::null(),
            )
        };

        if dw_error == ERROR_SUCCESS.0 {
            let mut n_proc_info_needed = 0;
            let mut n_proc_info = max_return as _;
            let mut rgaffectedapps = vec![RM_PROCESS_INFO::default(); max_return];
            let prgaffectedapps = rgaffectedapps.as_mut_ptr();
            let mut lpdwrebootreasons = 0;
            dw_error = unsafe {
                RmGetList(
                    dw_session,
                    &mut n_proc_info_needed,
                    &mut n_proc_info,
                    prgaffectedapps,
                    &mut lpdwrebootreasons,
                )
            };
            if dw_error == ERROR_SUCCESS.0 {
                if n_proc_info_needed > 0 {
                    let apps =
                        unsafe { slice::from_raw_parts(prgaffectedapps, n_proc_info_needed as _) };
                    let pids = apps
                        .iter()
                        .map(|f| f.Process.dwProcessId)
                        .collect::<Vec<_>>();

                    // Shut down all programs that have these files open:
                    // use windows::Win32::System::RestartManager::RmShutdown;
                    // let fnstatus = None; // callback, optionally provide closure here?
                    // dw_error = RmShutdown(dw_session, RmForceShutdown.0 as _, fnstatus);
                    unsafe {
                        RmEndSession(dw_session);
                        SetLastError(WIN32_ERROR(dw_error));
                    }
                    Ok(pids)
                } else {
                    unsafe {
                        RmEndSession(dw_session);
                        SetLastError(WIN32_ERROR(dw_error));
                    }
                    Ok(vec![])
                }
            } else {
                unsafe {
                    RmEndSession(dw_session);
                    SetLastError(WIN32_ERROR(dw_error));
                }
                Err(format!(
                    "rmgetlist {}: {}",
                    dw_error,
                    get_rmgetlist_err(dw_error)
                ))
            }
        } else {
            unsafe {
                RmEndSession(dw_session);
                SetLastError(WIN32_ERROR(dw_error));
            }
            Err(format!(
                "rmregisterresources {}: {}",
                dw_error,
                get_rmregisterresources_err(dw_error)
            ))
        }
    } else {
        unsafe {
            RmEndSession(dw_session);
            SetLastError(WIN32_ERROR(dw_error));
        }
        Err(format!(
            "rmstartsession {}: {}",
            dw_error,
            get_rmstartsession_err(dw_error)
        ))
    }
}

fn get_rmstartsession_err(err: u32) -> String {
    let msg = match err {
        0 => "The function completed successfully.",
        121 => "A Restart Manager function could not obtain a Registry write mutex in the allotted time. A system restart is recommended because further use of the Restart Manager is likely to fail.",
        160 => "One or more arguments are not correct. This error value is returned by the Restart Manager function if a NULL pointer or 0 is passed in a parameter that requires a non-null and non-zero value.",
        353 => "The maximum number of sessions has been reached.",
        29 => "The system cannot write to the specified device.",
        14 => "A Restart Manager operation could not complete because not enough memory was available.",
        _ => "",
    };
    String::from(msg)
}

fn get_rmregisterresources_err(err: u32) -> String {
    let msg = match err {
        0 => "The resources specified have been registered.",
        121 => "A Restart Manager function could not obtain a Registry write mutex in the allotted time. A system restart is recommended because further use of the Restart Manager is likely to fail.",
        160 => "One or more arguments are not correct. This error value is returned by Restart Manager function if a NULL pointer or 0 is passed in a parameter that requires a non-null and non-zero value.",
        29 => "An operation was unable to read or write to the registry.",
        14 => "A Restart Manager operation could not complete because not enough memory was available.",
        6 => "No Restart Manager session exists for the handle supplied.",
        _ => "",
    };
    String::from(msg)
}

fn get_rmgetlist_err(err: u32) -> String {
    let msg = match err {
        0 => "The function completed successfully.",
        234 => "This error value is returned by the RmGetList function if the rgAffectedApps buffer is too small to hold all application information in the list.",
        1223 => "The current operation is canceled by user.",
        121 => "A Restart Manager function could not obtain a Registry write mutex in the allotted time. A system restart is recommended because further use of the Restart Manager is likely to fail.",
        160 => "One or more arguments are not correct. This error value is returned by the Restart Manager function if a NULL pointer or 0 is passed in a parameter that requires a non-null and non-zero value.",
        29 => "An operation was unable to read or write to the registry.",
        14 => "A Restart Manager operation could not complete because not enough memory was available.",
        6 => "No Restart Manager session exists for the handle supplied.",
        _ => "",
    };
    String::from(msg)
}

type DirEntryResult = Result<DirEntry, std::io::Error>;

fn scan<'a, U: AsRef<Path>>(src: &U, tx: Sender<(DirEntryResult, u64)>, scope: &Scope<'a>) {
    let dir = match fs::read_dir(src) {
        Ok(ok) => ok,
        Err(_err) => {
            /* println!("{:?}", err); */
            return;
        }
    };
    dir.into_iter().for_each(|entry| {
        let info = match entry.as_ref() {
            Ok(ok) => ok,
            Err(_err) => {
                /* println!("{:?}", err); */
                return;
            }
        };
        let path = info.path();

        if path.is_dir() {
            let tx = tx.clone();
            scope.spawn(move |s| scan(&path, tx, s))
        } else {
            // dbg!("{}", path.as_os_str().to_string_lossy());
            let size = match info.metadata() {
                Ok(ok) => ok,
                Err(_err) => {
                    /* println!("{:?}", err); */
                    return;
                }
            }
            .len();
            tx.send((entry, size)).unwrap();
        }
    });
}
