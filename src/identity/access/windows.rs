//! The Windows reader: the file's DACL, and the explicit one a new key is given.
//!
//! A mode is not a Windows idea. Who may open a file is decided by an access list,
//! so keeping the key to the accounts the rule allows means reading the file's DACL
//! — from the open descriptor, so the list that let the open succeed is the list
//! that is checked. Giving a new key its list is the other half, and that is done by
//! path: the handle `tempfile` creates is opened for reading and writing only, and
//! `WRITE_DAC` is granted only when it is asked for, so a list written through
//! that handle would be refused. The file is still empty at that point, so no key
//! byte is ever behind a list this module did not write.
//!
//! The link check is the one thing read from the path, because a handle does not
//! report that it was opened through a reparse point. That is not a hole: a link is
//! only a name for another file, and that file's DACL is checked on the handle, so
//! whatever is read was private first.
//!
//! The owner is read with the list: on Windows the owner may rewrite a DACL, so a
//! key file somebody else owns is theirs to open however the list reads — the same
//! hazard the unix rule answers by checking ownership. A file with no owner at all is
//! reported as owning nothing rather than attributed to an invented account, because
//! no account could be named for the repair. A new key file is given this process's
//! account as owner, after the list, because a token does not always choose itself as
//! the owner of the file it creates.
//!
//! The rule itself is not here. [`super::dacl_refusal`] decides; this module only
//! turns SIDs into accounts.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{addr_of_mut, null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAce, CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
    InitializeAcl, LookupAccountSidW, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SYSTEM_ALARM_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::PWSTR;

use super::{Account, Dacl, DaclEntry, Insecurity, Opening};

/// The most bytes a SID can take, and therefore the size of every buffer here
/// that holds one.
const SID_BUFFER: usize = SECURITY_MAX_SID_SIZE as usize;

/// Open the key file for reading, refusing a link or something that is not a
/// regular file.
///
/// The link check is by path: `symlink_metadata` is the only place a reparse point
/// can be seen, because the handle a later open returns does not report one. The
/// refusal is still sound against a swap between the two calls, since what the
/// handle leads to carries a DACL that [`check`] reads on that handle: a link is
/// followed only to a file that is private in its own right.
pub(super) fn open(path: &Path) -> io::Result<Opening> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Opening::Absent),
        Err(error) => return Err(error),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Ok(Opening::Refused(Insecurity::Symlink));
    }
    if !file_type.is_file() {
        return Ok(Opening::Refused(Insecurity::NotRegular));
    }
    Ok(Opening::File(File::open(path)?))
}

/// Check a directory that holds records: its access list and owner, read from a
/// handle opened for a directory.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` is what lets a directory be opened as a file at
/// all. The link check is by path, for the same reason [`open`]'s is: a handle does
/// not report that it was reached through a reparse point, and the directory the
/// handle leads to is checked in its own right.
pub(super) fn check_dir(dir: &Path) -> io::Result<Option<Insecurity>> {
    let metadata = std::fs::symlink_metadata(dir)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Ok(Some(Insecurity::Symlink));
    }
    if !file_type.is_dir() {
        return Ok(Some(Insecurity::NotRegular));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?;
    check(&file)
}

pub(super) fn check(file: &File) -> io::Result<Option<Insecurity>> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the handle is open for the whole call, and `sd` receives the one
    // allocation `GetSecurityInfo` makes, which is freed below whatever happens
    // in between. `owner` points into that allocation.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut sd,
        )
    };
    if status != 0 {
        // This call answers with the code itself instead of setting the thread's
        // last error, so `last_os_error` would report a stale one.
        return Err(win32_error(status));
    }
    let answer = dacl_of(owner, dacl, sd);
    // SAFETY: `sd` is the descriptor `GetSecurityInfo` returned, this is its only
    // free, and everything read out of it has been copied by now.
    unsafe {
        LocalFree(sd);
    }
    answer.map(|dacl| super::dacl_refusal(&dacl))
}

/// Give a freshly created key file, or the `peers/` directory that holds records, an
/// explicit DACL naming only the owner, `SYSTEM` and `Administrators`, with
/// inheritance switched off, and make this process's account its owner.
///
/// Three accounts and not one: a backup or an antivirus tool that could not read
/// the key would make an operator loosen the check, so the list is the same one
/// [`super::dacl_refusal`] accepts, written by us rather than inherited.
///
/// The owner matters as much as the list: a token does not always choose the owner
/// of the file it creates — an elevated administrator's token defaults its new
/// objects to `Administrators` — so this sets the owner back to the account the
/// process runs as, the only ownership [`super::dacl_refusal`] accepts.
///
/// Both are applied by path: the handle `tempfile` creates for a new key has no
/// `WRITE_DAC`, and a directory is hardened before it is opened at all. For a key the
/// caller reads them back through the handle before writing a key byte, so no private
/// half ever sits behind the wrong access; for the directory the read-back is
/// `check_directory`, which refuses anything this call did not write.
pub(super) fn make_private(path: &Path) -> io::Result<()> {
    let owner = me()?;
    let system = well_known(WinLocalSystemSid)?;
    let administrators = well_known(WinBuiltinAdministratorsSid)?;
    let sids = [sid_ptr(&owner), sid_ptr(&system), sid_ptr(&administrators)];
    let acl_length = size_of::<ACL>() + sids.iter().copied().map(ace_length).sum::<usize>();
    // `usize` words rather than bytes, so the ACL starts on a word boundary: it
    // holds pointers, and the platform reads them as such.
    let mut block = vec![0usize; acl_length.div_ceil(size_of::<usize>())];
    let acl = block.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl` is `acl_length` bytes of `block` — an ACL header and one ACE
    // per SID — and nothing else writes to them.
    if unsafe { InitializeAcl(acl, count(acl_length), ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    for sid in sids {
        // SAFETY: `acl_length` counted one ACE per SID, so each write fits.
        if unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // The name the platform takes is UTF-16 and null-terminated. An embedded null
    // would end the name early and set the list on a different file, so it is
    // refused here rather than truncated.
    let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
    if name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{}` contains a null", path.display()),
        ));
    }
    name.push(0);
    // `PROTECTED_DACL_SECURITY_INFORMATION` is what cuts inheritance: without it
    // the directory's entries would be added to these three.
    // SAFETY: `name` is null-terminated and alive for the call, and `acl` is a
    // whole ACL whose ACEs point at SIDs that are alive until it returns.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    if status != 0 {
        return Err(win32_error(status));
    }
    // The owner, in a second call: the list just written grants this process account
    // full control, which carries the right to set the owner, and by now that list is
    // what the access check reads. No restore privilege is involved — an object's
    // owner may always take itself.
    // SAFETY: `name` is null-terminated and alive for the call, and `owner` is a
    // whole SID in this frame; no DACL is passed, so the list just written stays.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            sid_ptr(&owner),
            null_mut(),
            null(),
            null(),
        )
    };
    if status != 0 {
        return Err(win32_error(status));
    }
    Ok(())
}

/// The facts a returned descriptor and DACL hold.
fn dacl_of(owner: PSID, dacl: *const ACL, sd: PSECURITY_DESCRIPTOR) -> io::Result<Dacl> {
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `sd` is live for the caller's whole function, which frees it only
    // after this returns.
    if unsafe { GetSecurityDescriptorControl(sd, &raw mut control, &raw mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let protected = control & SE_DACL_PROTECTED != 0;
    let accounts = Accounts::read()?;
    // An owner may rewrite the list, so a file somebody else owns is theirs to
    // open however the list reads — the same reason the unix rule checks
    // ownership. A file with no owner at all is a refusal of its own: `None` says
    // no account can be named, rather than inventing one. An owner the platform can
    // neither name nor spell is a failure to read the owner, not an ownerless file.
    let owner = if owner.is_null() {
        None
    } else {
        Some(
            accounts
                .of(owner)
                .ok_or_else(|| io::Error::other("the owner of the file cannot be named"))?,
        )
    };
    if dacl.is_null() {
        // No list at all, which is not an empty list: it grants everything to
        // everyone. The fact is recorded, and `dacl_refusal` is what refuses it.
        return Ok(Dacl {
            owner,
            present: false,
            protected,
            entries: Vec::new(),
        });
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is the ACL inside `sd`, and `size` is the structure that
    // `AclSizeInformation` fills.
    let read = unsafe {
        GetAclInformation(
            dacl,
            addr_of_mut!(size).cast::<c_void>(),
            count(size_of::<ACL_SIZE_INFORMATION>()),
            AclSizeInformation,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut entries = Vec::with_capacity(size.AceCount as usize);
    for index in 0..size.AceCount {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: `dacl` is live, and `index` is below the count just read.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE begins with its type byte.
        let kind = unsafe { ace.cast::<u8>().read() };
        let allows = match u32::from(kind) {
            ACCESS_ALLOWED_ACE_TYPE => true,
            ACCESS_DENIED_ACE_TYPE => false,
            // An audit or alarm entry grants nothing at all.
            SYSTEM_AUDIT_ACE_TYPE | SYSTEM_ALARM_ACE_TYPE => continue,
            // Anything else — an object or callback grant, a kind this reader does
            // not parse — is recorded as an allowance by an account it cannot name,
            // which `dacl_refusal` refuses. Reading past it would be the one way a
            // grant could be hidden from this check.
            _ => {
                entries.push(DaclEntry {
                    allows: true,
                    account: None,
                });
                continue;
            }
        };
        // SAFETY: an allow and a deny ACE differ only in the type byte and the
        // flags; the mask and then the SID sit at the same offsets in both, so
        // one field names the SID for the two kinds matched above.
        let sid =
            unsafe { addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast::<c_void>() };
        entries.push(DaclEntry {
            allows,
            account: accounts.of(sid),
        });
    }
    Ok(Dacl {
        owner,
        present: true,
        protected,
        entries,
    })
}

/// The SIDs of the accounts a DACL entry may name besides a stranger: this
/// process's user, `SYSTEM`, and `Administrators`.
struct Accounts {
    me: [u8; SID_BUFFER],
    system: [u8; SID_BUFFER],
    administrators: [u8; SID_BUFFER],
}

impl Accounts {
    fn read() -> io::Result<Self> {
        Ok(Self {
            me: me()?,
            system: well_known(WinLocalSystemSid)?,
            administrators: well_known(WinBuiltinAdministratorsSid)?,
        })
    }

    /// The account `sid` names, or `None` when the platform can neither name it nor
    /// spell it.
    fn of(&self, sid: PSID) -> Option<Account> {
        if equal(sid, &self.me) {
            return Some(Account::Owner);
        }
        if equal(sid, &self.system) {
            return Some(Account::System);
        }
        if equal(sid, &self.administrators) {
            return Some(Account::Administrators);
        }
        name(sid).map(Account::Other)
    }
}

/// Whether the SID an entry names is the one `buffer` holds.
fn equal(sid: PSID, buffer: &[u8; SID_BUFFER]) -> bool {
    // SAFETY: both arguments point at whole SIDs, and `EqualSid` only reads them.
    unsafe { EqualSid(sid, sid_ptr(buffer)) != 0 }
}

/// `buffer` as the SID pointer Windows takes. Nothing it is passed to writes
/// through it.
fn sid_ptr(buffer: &[u8; SID_BUFFER]) -> PSID {
    buffer.as_ptr().cast::<c_void>().cast_mut()
}

/// The SID of the account this process runs as.
fn me() -> io::Result<[u8; SID_BUFFER]> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `GetCurrentProcess` needs no argument and its pseudo-handle is
    // always open; `token` receives an owned handle, closed once below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = token_user(token);
    // SAFETY: `token` is the handle just opened, and this is its only close. The result
    // is deliberately ignored: a failed close cannot make a SID that was read wrong, and
    // turning it into the error would mask the one that ended the read and make the
    // ownership check fail for a reason unrelated to the file.
    unsafe { CloseHandle(token) };
    sid
}

/// The user SID out of an open token, copied out of the token's own buffer so the
/// buffer can be released.
fn token_user(token: HANDLE) -> io::Result<[u8; SID_BUFFER]> {
    let mut length = 0u32;
    // The first call only measures: with a null buffer it answers with an error
    // and the length that is needed.
    // SAFETY: a null buffer and a zero length are the documented way to ask for
    // the size, and `length` receives it.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &raw mut length) };
    let mut buffer = vec![0u8; length as usize];
    // SAFETY: `buffer` is `length` bytes, the size the call just reported, and
    // receives a `TOKEN_USER` followed by the SID it points at.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            length,
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // A byte vector is aligned for bytes only, and `TOKEN_USER` holds a pointer,
    // so the header is read without an alignment claim.
    // SAFETY: the call above filled `buffer` with a `TOKEN_USER` whose `Sid`
    // points into the same buffer, which is alive for the copy below.
    let user = unsafe { buffer.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
    let mut sid = [0u8; SID_BUFFER];
    // SAFETY: `sid` is `SECURITY_MAX_SID_SIZE` bytes, the most a SID can take,
    // and `user.User.Sid` points at a whole SID in `buffer`.
    if unsafe {
        CopySid(
            SECURITY_MAX_SID_SIZE,
            sid.as_mut_ptr().cast::<c_void>(),
            user.User.Sid,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

/// A well-known SID, written into a buffer of this frame.
fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<[u8; SID_BUFFER]> {
    let mut sid = [0u8; SID_BUFFER];
    let mut length = SECURITY_MAX_SID_SIZE;
    // SAFETY: `sid` is `SECURITY_MAX_SID_SIZE` bytes — the largest a SID can be —
    // and `length` says so. `CreateWellKnownSid` writes into the caller's memory
    // rather than allocating, so there is nothing here to free.
    if unsafe {
        CreateWellKnownSid(
            kind,
            null_mut(),
            sid.as_mut_ptr().cast::<c_void>(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

/// The bytes an allow ACE for `sid` takes: a header, the access mask, and the
/// SID. `SidStart` is that SID's first four bytes, so it is not counted twice.
fn ace_length(sid: PSID) -> usize {
    size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_length(sid) as usize
}

/// The length of a SID in bytes.
fn sid_length(sid: PSID) -> u32 {
    // SAFETY: `sid` points at a whole SID, from an ACE or from a buffer this
    // module filled.
    unsafe { GetLengthSid(sid) }
}

/// What the platform calls the account, or its SID in `S-1-…` form when the platform
/// has no name for it.
fn name(sid: PSID) -> Option<String> {
    /// A name and a domain are short; an account whose name is longer than this
    /// is reported as its SID rather than by truncation.
    const CHARS: u32 = 128;
    let mut account = [0u16; CHARS as usize];
    let mut domain = [0u16; CHARS as usize];
    let mut account_length = CHARS;
    let mut domain_length = CHARS;
    let mut kind = 0;
    // SAFETY: both buffers are `CHARS` wide characters and their lengths say so;
    // the call writes at most that many characters into each, and a name the
    // buffers cannot hold is refused with an error rather than overrun.
    let found = unsafe {
        LookupAccountSidW(
            null(),
            sid,
            account.as_mut_ptr(),
            &raw mut account_length,
            domain.as_mut_ptr(),
            &raw mut domain_length,
            &raw mut kind,
        )
    };
    if found == 0 {
        return sddl(sid);
    }
    // On success the lengths the call answers with exclude the terminators; only the
    // failing case's length is documented to include one.
    let account = String::from_utf16_lossy(&account[..account_length as usize]);
    if domain_length == 0 {
        return Some(account);
    }
    let domain = String::from_utf16_lossy(&domain[..domain_length as usize]);
    Some(format!("{domain}\\{account}"))
}

/// A SID the platform has no name for, in the SDDL form (`S-1-5-21-…`).
///
/// The conversion is the platform's own, not a copy of the format kept here, so the
/// spelling is the one the system tools print. `icacls` takes it in `/grant`,
/// `/remove:g` and `/setowner` with a leading `*`, so an operator can act on an account
/// the message names by its SID even when the platform cannot name it — a service
/// account on a domain controller this machine cannot reach is the case that gets here.
/// `None` when the platform cannot spell the SID either, which leaves the entry
/// unattributable rather than named by a guess.
fn sddl(sid: PSID) -> Option<String> {
    let mut text: PWSTR = null_mut();
    // SAFETY: `sid` points at a whole SID, and `text` receives the one allocation this
    // call makes, freed below.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return None;
    }
    // SAFETY: the call answered with a NUL-terminated UTF-16 string in `text`.
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: those `length` units belong to that string, which is alive until the free.
    let spelled = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    // SAFETY: `text` is the allocation this call made, and this is its only free.
    unsafe {
        LocalFree(text.cast());
    }
    Some(spelled)
}

/// A byte count as `u32`, the width the Win32 calls that take one want.
///
/// What is counted here is a descriptor, an ACL of three entries, or one
/// structure: a few hundred bytes, so the cast is exact.
#[allow(clippy::cast_possible_truncation)]
fn count(bytes: usize) -> u32 {
    bytes as u32
}

/// A code a Win32 call answered with, as the error it is.
fn win32_error(status: u32) -> io::Error {
    // A Win32 error is a 32-bit value that `from_raw_os_error` takes as `i32`
    // bits, so a wrap-around is the intended reading, not a loss.
    #[allow(clippy::cast_possible_wrap)]
    let code = status as i32;
    io::Error::from_raw_os_error(code)
}
