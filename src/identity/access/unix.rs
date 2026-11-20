//! The unix reader: mode bits and ownership, plus the extended access list on
//! macOS.
//!
//! `symlink_metadata` would answer about a link rather than about the file a link
//! points at; the descriptor does not have that problem, so the file is opened
//! with `O_NOFOLLOW` and everything is read from the descriptor.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::{Insecurity, Opening, unix_refusal};

pub(super) fn open(path: &Path) -> io::Result<Opening> {
    let mut options = OpenOptions::new();
    // `O_NOFOLLOW` refuses a link outright, `O_NONBLOCK` keeps a FIFO from
    // waiting for a writer before it is refused as not a regular file.
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    match options.open(path) {
        Ok(file) => Ok(Opening::File(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Opening::Absent),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            Ok(Opening::Refused(Insecurity::Symlink))
        }
        Err(error) => Err(error),
    }
}

/// Pin the mode of a new key file to its owner alone.
///
/// The crate that creates it asks for 0600 already, so this changes nothing in
/// practice; it is the step that makes "the key file is private" a thing this crate
/// did rather than a thing a dependency promised, and the same step Windows fills
/// with an explicit DACL.
pub(super) fn make_private(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

pub(super) fn check(file: &File) -> io::Result<Option<Insecurity>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(Some(Insecurity::NotRegular));
    }
    let me = me();
    if let Some(reason) = unix_refusal(metadata.mode() & 0o777, metadata.uid(), me) {
        return Ok(Some(reason));
    }
    #[cfg(target_os = "macos")]
    {
        // A mode is not the whole story on macOS: a 0600 file can still carry an
        // extended access entry that grants everyone read. The account is read once
        // and decides both facts: whose the file is, and whether an entry names it.
        extended_entries(file, me)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(None)
    }
}

/// The account this process runs as: the effective account, which is the one the
/// kernel checks an open against.
fn me() -> u32 {
    // SAFETY: `geteuid` reads one process property and touches no memory.
    unsafe { libc::geteuid() }
}

/// The login name the platform has for `uid`, when it has one.
///
/// Only a refusal that already happened reads this, to spell `nobody` rather than
/// `4294967294`. An account with no directory entry — a deleted account, an id from
/// another host — has no name, and the refusal reports its number instead of failing.
pub(super) fn account_name(uid: u32) -> Option<String> {
    // The re-entrant call fills this frame's buffer, so two threads formatting a
    // refusal at once cannot overwrite each other's answer. A name past the buffer
    // is answered with an error, which becomes "no name" rather than a panic.
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = [0u8; 1024];
    let mut answer: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `answer` receives a pointer into `entry` or is set to null; `buffer`
    // is the storage the call may fill and `len` is that storage's length.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut answer,
        )
    };
    if status != 0 || answer.is_null() {
        return None;
    }
    // SAFETY: a non-null answer points at the entry the call just filled.
    let entry = unsafe { entry.assume_init() };
    if entry.pw_name.is_null() {
        return None;
    }
    // SAFETY: `pw_name` is that entry's null-terminated login name.
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) };
    name.to_str().ok().map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn extended_entries(file: &File, me: u32) -> io::Result<Option<Insecurity>> {
    use std::os::fd::AsRawFd;

    // `sys/acl.h` defines `ACL_MAX_ENTRIES` as 128; this ceiling sits above it, so a
    // list longer than the platform allows still cannot spin the loop. An entry that
    // allows is tagged `ACL_EXTENDED_ALLOW` (a deny is `ACL_EXTENDED_DENY`).
    const MAX_ENTRIES: usize = 169;
    const EXTENDED_ALLOW: u32 = 1;

    let acl = ffi::get_fd(file.as_raw_fd());
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // Two answers mean "nothing is granted beyond the mode", and refusing on
        // either would refuse every key written on this platform: Darwin reports a
        // file with no extended entries as `ENOENT` rather than as an empty list,
        // and a volume without ACL support reports `ENOTSUP` or `EOPNOTSUPP`.
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTSUP | libc::EOPNOTSUPP) => Ok(None),
            _ => Err(error),
        };
    }
    // Darwin answers -1 both at the end of the list and on an error, so the cursor
    // itself cannot say which it was: that one ambiguity is an accepted residual,
    // since no API here separates them. A failure to read an entry that *is* there
    // can be told apart, and is: that answer is an error, and an error is a refusal —
    // a list shortened by one unreadable entry could hide the very entry that
    // grants access.
    let mut entries = Vec::new();
    let mut read = Ok(());
    for index in 0..MAX_ENTRIES {
        match ffi::entry(acl, index == 0, me) {
            Ok(Some((tag, owner))) => entries.push(super::Entry {
                allows: tag == EXTENDED_ALLOW,
                owner,
            }),
            Ok(None) => break,
            Err(error) => {
                read = Err(error);
                break;
            }
        }
    }
    ffi::free(acl);
    read?;
    Ok(super::acl_refusal(&entries))
}

/// The six Darwin declarations the reader needs and `libc` does not provide: the five
/// `sys/acl.h` calls, and `mbr_uuid_to_id` from `<membership.h>`, which turns an
/// entry's UUID into a directory account. The crate takes no dependency on a binding
/// for them: a handful of declarations are smaller than a crate that wraps them.
#[cfg(target_os = "macos")]
mod ffi {
    use std::ffi::{c_int, c_void};

    /// `ACL_TYPE_EXTENDED` from `sys/acl.h`.
    const ACL_TYPE_EXTENDED: u32 = 0x100;

    #[repr(C)]
    pub(super) struct Acl {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct AclEntry {
        _private: [u8; 0],
    }

    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, acl_type: u32) -> *mut Acl;
        fn acl_get_entry(acl: *mut Acl, entry_id: c_int, entry: *mut *mut AclEntry) -> c_int;
        fn acl_get_tag_type(entry: *mut AclEntry, tag: *mut u32) -> c_int;
        fn acl_get_qualifier(entry: *mut AclEntry) -> *mut c_void;
        fn acl_free(object: *mut c_void) -> c_int;
        fn mbr_uuid_to_id(uuid: *const c_void, id: *mut u32, id_type: *mut c_int) -> c_int;
    }

    pub(super) fn get_fd(fd: std::os::fd::RawFd) -> *mut Acl {
        // SAFETY: a plain call with a live descriptor; the result is either null or
        // an ACL this module frees exactly once.
        unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) }
    }

    /// The entry the cursor is on, as `(tag, names the owner)`, or nothing at the
    /// end of the list.
    ///
    /// Darwin's `acl_get_entry` answers 0 for an entry it found and -1 otherwise,
    /// not the 1/0 POSIX.1e describes, so the return value is what ends the loop; the
    /// pointer is checked too, because an answer of 0 must come with an entry. An entry
    /// that is there but cannot be read is an error: the caller must not carry on with
    /// a shorter list than the file's.
    pub(super) fn entry(
        acl: *mut Acl,
        first: bool,
        me: u32,
    ) -> std::io::Result<Option<(u32, bool)>> {
        let mut entry = std::ptr::null_mut();
        let id = if first { 0 } else { -1 };
        // SAFETY: `acl` is held by the caller until the loop ends; the entry
        // pointer it writes belongs to that ACL and is not freed here.
        unsafe {
            if acl_get_entry(acl, id, &raw mut entry) != 0 || entry.is_null() {
                return Ok(None);
            }
            let mut tag = 0u32;
            if acl_get_tag_type(entry, &raw mut tag) != 0 {
                return Err(std::io::Error::other(
                    "an extended access entry's tag could not be read",
                ));
            }
            Ok(Some((tag, names_owner(entry, me))))
        }
    }

    /// Whether the entry names the account this process runs as.
    ///
    /// The qualifier is a UUID, and `mbr_uuid_to_id` turns it into a directory
    /// account. An entry this cannot resolve — no qualifier, or a UUID the mapping does
    /// not know — is not attributable to the owner either, and refusing it costs one
    /// `chmod -N`.
    fn names_owner(entry: *mut AclEntry, me: u32) -> bool {
        /// `ID_TYPE_UID` from `membership.h`.
        const ID_TYPE_UID: c_int = 0;
        // SAFETY: `entry` is live and owned by an ACL the caller still holds.
        unsafe {
            let qualifier = acl_get_qualifier(entry);
            if qualifier.is_null() {
                return false;
            }
            let mut id = 0u32;
            let mut kind = -1;
            let mapped = mbr_uuid_to_id(qualifier, &raw mut id, &raw mut kind);
            acl_free(qualifier);
            mapped == 0 && kind == ID_TYPE_UID && id == me
        }
    }

    pub(super) fn free(acl: *mut Acl) {
        // SAFETY: `acl` came from `get_fd` and is freed once.
        unsafe {
            acl_free(acl.cast::<c_void>());
        }
    }
}
