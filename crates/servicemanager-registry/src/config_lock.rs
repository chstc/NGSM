use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Duration;

use servicemanager_core::{validate_service_name, Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, HANDLE, HLOCAL, LPARAM, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Globalization::{LCMapStringEx, LCMAP_UPPERCASE, LOCALE_NAME_INVARIANT};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{CreateMutexExW, ReleaseMutex, WaitForSingleObject};

/// A reentrant, cross-process service-writer lock. The owning thread must drop
/// each acquired guard; this type deliberately is neither Send nor Sync.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<servicemanager_registry::ServiceConfigGuard>();
/// ```
pub struct ServiceConfigGuard {
    handle: HANDLE,
    abandoned: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ServiceConfigGuard {
    /// An earlier writer exited while holding the lock. Re-read registry state;
    /// its last update may have been interrupted.
    pub fn was_abandoned(&self) -> bool {
        self.abandoned
    }
}

impl Drop for ServiceConfigGuard {
    fn drop(&mut self) {
        // SAFETY: this guard owns one acquisition and one handle, and !Send
        // keeps release on the acquiring thread. Windows mutexes are reentrant.
        unsafe {
            let _ = ReleaseMutex(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Serialize writers to one service for at most five seconds. Case aliases
/// share a Global named mutex; unrelated services use distinct stable names.
/// Reads do not acquire this lock or require additional access.
pub fn lock_service_config(name: &str) -> Result<ServiceConfigGuard> {
    lock_with_timeout(name, Duration::from_secs(5))
}

pub(crate) fn windows_name_key(name: &str) -> Result<Vec<u16>> {
    let source: Vec<u16> = name.encode_utf16().collect();
    if source.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: source is a valid counted UTF-16 slice; this probes the size of
    // the invariant Windows uppercase mapping, independent of user locale.
    let needed = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            &source,
            None,
            None,
            None,
            LPARAM(0),
        )
    };
    if needed == 0 {
        return Err(Error::Registry(format!(
            "cannot normalize registry name: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut out = vec![0; needed as usize];
    // SAFETY: output has the capacity returned by the probe above.
    let written = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            &source,
            Some(&mut out),
            None,
            None,
            LPARAM(0),
        )
    };
    if written != needed {
        return Err(Error::Registry("Windows name normalization failed".into()));
    }
    Ok(out)
}

fn mutex_name(name: &str) -> Result<Vec<u16>> {
    validate_service_name(name)?;
    // Stable FNV-1a 128-bit over the OS-normalized UTF-16 name; no per-process
    // hash seed, locale dependence or MAX_PATH-sized name can split a lock.
    let mut hash = 0x6c62272e07bb014262b821756295c58du128;
    for byte in windows_name_key(name)?
        .into_iter()
        .flat_map(u16::to_le_bytes)
    {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x0000000001000000000000000000013bu128);
    }
    Ok(format!("Global\\NGSM.Config.v1.{hash:032x}")
        .encode_utf16()
        .chain(Some(0))
        .collect())
}

fn lock_with_timeout(name: &str, timeout: Duration) -> Result<ServiceConfigGuard> {
    let name = mutex_name(name)?;
    // Only SYSTEM, administrators and the creator/owner can synchronize and
    // release. OW also makes unprivileged same-user test/writer processes work
    // without granting all authenticated users access to privileged locks.
    let sddl: Vec<u16> = "D:P(A;;0x00100001;;;SY)(A;;0x00100001;;;BA)(A;;0x00100001;;;OW)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: SDDL is NUL-terminated and descriptor is a valid out-parameter.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| Error::Registry(format!("configuration-lock ACL: {e}")))?;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: attributes and name live through creation. The returned handle
    // requests only SYNCHRONIZE | MUTEX_MODIFY_STATE, not MUTEX_ALL_ACCESS.
    let created =
        unsafe { CreateMutexExW(Some(&attributes), PCWSTR(name.as_ptr()), 0, 0x0010_0001) };
    // SAFETY: the descriptor was allocated by the SDDL converter; CreateMutexEx
    // has copied it and no pointer into it remains in use.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    let handle = created.map_err(|e| Error::Registry(format!("configuration lock: {e}")))?;
    let millis = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
    // SAFETY: handle is a live mutex with SYNCHRONIZE access.
    let wait = unsafe { WaitForSingleObject(handle, millis) };
    if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
        return Ok(ServiceConfigGuard {
            handle,
            abandoned: wait == WAIT_ABANDONED,
            _thread_bound: PhantomData,
        });
    }
    let error = if wait == WAIT_TIMEOUT {
        Error::Registry("timed out waiting for the service configuration writer lock".into())
    } else {
        Error::Registry(format!(
            "configuration lock wait: {}",
            std::io::Error::last_os_error()
        ))
    };
    // SAFETY: failed waits did not acquire ownership; close the owned handle.
    unsafe {
        let _ = CloseHandle(handle);
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> String {
        format!(
            "NGSM-éя-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn config_lock_names_are_bounded_stable_and_validate_service_names() {
        let name = "é".repeat(256);
        let encoded = mutex_name(&name).unwrap();
        assert_eq!(encoded, mutex_name(&name.to_uppercase()).unwrap());
        assert!(encoded.len() < 100);
        assert_eq!(encoded.last(), Some(&0));
        assert_ne!(
            mutex_name("ServiceA").unwrap(),
            mutex_name("ServiceB").unwrap()
        );
        assert!(mutex_name(&"x".repeat(257)).is_err());
        assert!(mutex_name("bad\\name").is_err());
    }

    #[test]
    fn config_lock_is_reentrant_and_case_aliases_serialize() {
        let name = fixture();
        assert_eq!(
            windows_name_key(&name).unwrap(),
            windows_name_key(&name.to_lowercase()).unwrap(),
            "{name} => {}",
            name.to_lowercase()
        );
        let outer = lock_service_config(&name).unwrap();
        let inner = lock_service_config(&name.to_uppercase()).unwrap();
        let other = name.to_lowercase();
        let error = std::thread::spawn(move || {
            lock_with_timeout(&other, Duration::from_millis(80))
                .err()
                .unwrap()
                .to_string()
        })
        .join()
        .unwrap();
        assert!(error.contains("timed out"), "{error}");
        drop(inner);
        drop(outer);
        assert!(lock_service_config(&name).is_ok());
    }

    #[test]
    fn config_lock_does_not_serialize_unrelated_services() {
        let name = fixture();
        let _guard = lock_service_config(&name).unwrap();
        let other = format!("{name}-other");
        assert!(std::thread::spawn(move || {
            lock_with_timeout(&other, Duration::from_millis(80)).is_ok()
        })
        .join()
        .unwrap());
    }

    #[test]
    fn cross_process_lock_probe() {
        let Ok(name) = std::env::var("NGSM_CONFIG_LOCK_TEST_NAME") else {
            return;
        };
        let result = lock_with_timeout(&name, Duration::from_millis(150));
        if std::env::var("NGSM_CONFIG_LOCK_TEST_BLOCKED").is_ok() {
            assert!(result.err().unwrap().to_string().contains("timed out"));
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn config_lock_serializes_real_processes_and_unicode_case_aliases() {
        let name = fixture();
        let guard = lock_service_config(&name).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "config_lock::tests::cross_process_lock_probe"])
            .env("NGSM_CONFIG_LOCK_TEST_NAME", name.to_uppercase())
            .env("NGSM_CONFIG_LOCK_TEST_BLOCKED", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        drop(guard);
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "config_lock::tests::cross_process_lock_probe"])
            .env("NGSM_CONFIG_LOCK_TEST_NAME", name.to_lowercase())
            .env_remove("NGSM_CONFIG_LOCK_TEST_BLOCKED")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn config_lock_recovers_an_abandoned_owner() {
        let name = fixture();
        let thread_name = name.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let guard = lock_service_config(&thread_name).unwrap();
            tx.send(guard.handle.0 as usize).unwrap();
            finish_rx.recv().unwrap();
            std::mem::forget(guard);
        });
        let leaked_handle = rx.recv().unwrap();
        finish_tx.send(()).unwrap();
        thread.join().unwrap();
        let recovered = lock_service_config(&name).unwrap();
        assert!(recovered.was_abandoned());
        // SAFETY: ownership of the forgotten guard's handle was transferred
        // above; the owner thread has exited and this closes it exactly once.
        unsafe {
            CloseHandle(HANDLE(leaked_handle as *mut _)).unwrap();
        }
    }
}
