use super::*;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE};

#[test]
fn native_mutex_denies_an_existing_object_without_sync_permission() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.log");
    let handle = create_event_mutex(&path, "D:P", 0).unwrap();
    let denied = EventLock::acquire(&path, 20).err().unwrap();
    // SAFETY: this is the owned, zero-access fixture handle created above.
    unsafe {
        let _ = CloseHandle(handle);
    }
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn service_restricted_token_has_minimal_mutex_access_but_unlisted_sid_is_denied() {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows::core::PCWSTR;
    use windows::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, ImpersonateLoggedOnUser, RevertToSelf,
        WinNullSid, WinServiceSid, DISABLE_MAX_PRIVILEGE, PSID, SID_AND_ATTRIBUTES,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{CreateMutexExW, GetCurrentProcess, OpenProcessToken};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.log");
    let _guard = EventLock::acquire(&path, 100).unwrap();
    let name = mutex_name(&path).unwrap();
    let mut token = HANDLE::default();
    // SAFETY: opens a new owned token handle for this test process only.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
            &mut token,
        )
    }
    .unwrap();
    // SAFETY: transfer the new token handle to RAII ownership.
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    for (sid_type, permitted) in [(WinServiceSid, true), (WinNullSid, false)] {
        let mut sid = [0u64; 9];
        let mut size = std::mem::size_of_val(&sid) as u32;
        let sid_pointer = PSID(sid.as_mut_ptr().cast());
        // SAFETY: the aligned SID buffer has the advertised capacity.
        unsafe { CreateWellKnownSid(sid_type, None, Some(sid_pointer), &mut size) }.unwrap();
        let restricted_sid = SID_AND_ATTRIBUTES {
            Sid: sid_pointer,
            Attributes: 0,
        };
        let mut restricted = HANDLE::default();
        // SAFETY: the source token and SID slice remain live; the output is a new token.
        unsafe {
            CreateRestrictedToken(
                HANDLE(token.as_raw_handle()),
                DISABLE_MAX_PRIVILEGE,
                None,
                None,
                Some(&[restricted_sid]),
                &mut restricted,
            )
        }
        .unwrap();
        // SAFETY: transfer the new token handle once.
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted.0) };
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                // SAFETY: restores this test thread's own prior process identity.
                unsafe {
                    let _ = RevertToSelf();
                }
            }
        }
        // SAFETY: impersonates only a restricted derivative of our own token on this test thread.
        unsafe { ImpersonateLoggedOnUser(HANDLE(restricted.as_raw_handle())) }.unwrap();
        let revert = Revert;
        // SAFETY: the existing mutex name is terminated; this requests only sync/modify access.
        let result = unsafe { CreateMutexExW(None, PCWSTR(name.as_ptr()), 0, 0x0010_0001) };
        drop(revert);
        let granted = match result {
            Ok(handle) => {
                // SAFETY: close the newly opened, unowned mutex handle without releasing it.
                unsafe {
                    let _ = CloseHandle(handle);
                }
                true
            }
            Err(error) => {
                assert_eq!(error.code().0 & 0xffff, 5);
                false
            }
        };
        assert_eq!(
            granted, permitted,
            "restricted SID class must determine synchronization access"
        );
    }
}
use servicemanager_win32::JobObject;

#[test]
fn minimal_native_mutex_access_succeeds_but_all_access_is_denied() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.log");
    let _guard = EventLock::acquire(&path, 100).unwrap();
    match create_event_mutex(&path, EVENT_MUTEX_SDDL, 0x001f_0001) {
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        Ok(handle) => {
            // SAFETY: this is the unexpected owned handle, closed before failing the test.
            unsafe {
                let _ = CloseHandle(handle);
            }
            panic!("the event mutex must not grant MUTEX_ALL_ACCESS");
        }
    }
}

#[test]
fn native_mutex_timeout_is_destination_scoped_and_dot_aliases_coordinate() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.log");
    let alias = directory.path().join(".").join("events.log");
    let other_directory = directory.path().join("independent");
    std::fs::create_dir(&other_directory).unwrap();
    let other = other_directory.join("events.log");
    let _guard = EventLock::acquire(&path, 100).unwrap();
    let worker = std::thread::spawn(move || {
        assert_eq!(
            EventLock::acquire(&alias, 20).err().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
        let _independent = EventLock::acquire(&other, 20).unwrap();
    });
    worker.join().unwrap();
}

#[test]
fn native_mutex_recovers_an_abandoned_owner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.log");
    let worker_path = path.clone();
    let handle = std::thread::spawn(move || {
        let guard = EventLock::acquire(&worker_path, 100).unwrap();
        let handle = guard.0 .0 as usize;
        std::mem::forget(guard);
        handle
    })
    .join()
    .unwrap();
    let _recovered = EventLock::acquire(&path, 100).unwrap();
    // SAFETY: the joined thread intentionally transferred this one leaked handle.
    // Its mutex ownership was abandoned, so close it without ReleaseMutex.
    unsafe {
        let _ = CloseHandle(HANDLE(handle as *mut std::ffi::c_void));
    }
}

#[test]
#[ignore = "isolated cross-process event-log writer fixture"]
fn child_writer() {
    let index: u32 = std::env::var("NGSM_EVENT_CHILD_INDEX")
        .unwrap()
        .parse()
        .unwrap();
    let writer = EventWriter::for_service(format!("EventChild{index}"));
    for record in 0..25 {
        writer.started(index * 1000 + record);
    }
}

#[test]
fn real_cross_process_writers_and_rotation_keep_every_record() {
    let _guard = crate::TEST_PROGRAM_DATA_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let directory = tempfile::tempdir().unwrap();
    std::env::set_var("NGSM_PROGRAM_DATA_DIR", directory.path());
    let active = paths::events_log().unwrap();
    let mut seed = vec![b'x'; ROTATION_THRESHOLD_BYTES as usize - 200];
    seed.push(b'\n');
    std::fs::write(&active, seed).unwrap();
    let job = JobObject::new_kill_on_close().unwrap();
    let mut children = Vec::new();
    for index in 0..4 {
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "event_log::windows_tests::child_writer",
                "--ignored",
                "--nocapture",
            ])
            .env("NGSM_PROGRAM_DATA_DIR", directory.path())
            .env("NGSM_EVENT_CHILD_INDEX", index.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(4)
            .spawn()
            .unwrap();
        job.assign_child(&child).unwrap();
        job.pin_child(&child).unwrap().resume().unwrap();
        children.push(child);
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    for child in &mut children {
        loop {
            match child.try_wait().unwrap() {
                Some(status) => {
                    assert!(status.success());
                    break;
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "fixture writer must finish within its deadline"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
    let mut records = Vec::new();
    for path in std::iter::once(active).chain(
        (1..=paths::BACKUP_RETENTION_COUNT).map(|index| paths::events_log_backup_n(index).unwrap()),
    ) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        records.extend(
            text.lines()
                .filter(|line| !line.starts_with('x'))
                .map(|line| {
                    serde_json::from_str::<EventRecord>(line)
                        .expect("concurrent record must not be torn")
                }),
        );
    }
    assert_eq!(records.len(), 100);
    let mut identities: Vec<_> = records
        .into_iter()
        .map(|record| record.pid.unwrap())
        .collect();
    identities.sort_unstable();
    identities.dedup();
    assert_eq!(identities.len(), 100);
    assert!(paths::events_log_backup_n(1).unwrap().exists());
}
