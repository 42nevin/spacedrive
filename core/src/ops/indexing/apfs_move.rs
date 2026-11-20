//! Recover the missing half of a cold watcher event using a *live* witness
//! from this source's ledger. The kernel supplies a candidate path, never a
//! replacement UUID. An ordinary unlink is still an ordinary removal.
use super::{
	change_detection::should_filter_path, metadata::is_hidden_path, rules::RuleToggles,
	state::EntryKind, ArenaWriter, EntryMetadata, Seen, SourceStore,
};
use crate::context::CoreContext;
use sd_fs_watcher::{FsEvent, FsEventKind};
use sd_store::LiveObject;
use std::{
	ffi::{CStr, OsStr},
	fs::{File, OpenOptions},
	io,
	mem::MaybeUninit,
	os::{
		fd::AsRawFd,
		unix::{
			ffi::OsStrExt,
			fs::{MetadataExt, OpenOptionsExt},
		},
	},
	path::{Path, PathBuf},
	sync::Arc,
};

extern "C" {
	fn fsgetpath(
		buf: *mut libc::c_char,
		size: usize,
		fsid: *const libc::fsid_t,
		object: u64,
	) -> libc::ssize_t;
}

fn open_metadata(path: &Path) -> io::Result<File> {
	OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_EVTONLY | libc::O_NOFOLLOW_ANY)
		.open(path)
}

fn locate(root: &Path, witness: LiveObject) -> io::Result<Option<PathBuf>> {
	let dir = open_metadata(root)?;
	if dir.metadata()?.dev() != witness.device {
		return Ok(None);
	}
	let mut volume = MaybeUninit::<libc::statfs>::uninit();
	// SAFETY: valid directory fd, writable statfs; read only after success.
	if unsafe { libc::fstatfs(dir.as_raw_fd(), volume.as_mut_ptr()) } != 0 {
		return Err(io::Error::last_os_error());
	}
	let volume = unsafe { volume.assume_init() };
	if volume.f_flags & libc::MNT_LOCAL as u32 == 0
		|| unsafe { CStr::from_ptr(volume.f_fstypename.as_ptr()) }.to_bytes() != b"apfs"
	{
		return Ok(None);
	}
	let mut buf = [0u8; libc::PATH_MAX as usize];
	// SAFETY: the kernel receives the exact buffer length and a valid fsid.
	let n = unsafe {
		fsgetpath(
			buf.as_mut_ptr().cast(),
			buf.len(),
			&volume.f_fsid,
			witness.inode,
		)
	};
	if n < 0 {
		let e = io::Error::last_os_error();
		return if e.kind() == io::ErrorKind::NotFound {
			Ok(None)
		} else {
			Err(e)
		};
	}
	let name = CStr::from_bytes_until_nul(&buf[..n as usize]).map_err(io::Error::other)?;
	let path = PathBuf::from(OsStr::from_bytes(name.to_bytes()));
	if !path.starts_with(root) || path.to_str().is_none() || crate::config::is_managed(&path) {
		return Ok(None);
	}
	Ok(Some(path))
}

fn verify(path: PathBuf, witness: LiveObject) -> io::Result<Option<EntryMetadata>> {
	let fd = open_metadata(&path)?;
	let m = fd.metadata()?;
	if LiveObject::from_metadata(&m) != Some(witness) {
		return Ok(None);
	}
	Ok(Some(EntryMetadata {
		kind: EntryKind::File,
		size: m.len(),
		modified: m.modified().ok(),
		accessed: m.accessed().ok(),
		created: Some(witness.birth),
		inode: Some(witness.inode),
		live_object: Some(witness),
		permissions: Some(m.mode()),
		uid: Some(m.uid()),
		gid: Some(m.gid()),
		link_target: None,
		is_hidden: is_hidden_path(&path),
		path,
	}))
}

/// True if the event is fully accounted for; otherwise its ordinary handler
/// still runs (notably for a replacement that arrived at the vacated name).
pub(super) async fn account(
	context: &Arc<CoreContext>,
	writer: &ArenaWriter,
	store: &Arc<SourceStore>,
	event: &FsEvent,
	rules: RuleToggles,
) -> anyhow::Result<bool> {
	if !matches!(event.kind, FsEventKind::Remove | FsEventKind::Create)
		|| event.is_dir() == Some(true)
	{
		return Ok(false);
	}
	let now = match tokio::fs::symlink_metadata(&event.path).await {
		Ok(m) => LiveObject::from_metadata(&m),
		Err(e) if e.kind() == io::ErrorKind::NotFound => None,
		Err(e) => return Err(e.into()),
	};
	let Some((old, stamp)) = store
		.live_binding(&event.path, now.map(|w| w.inode))
		.await?
	else {
		return Ok(false);
	};
	if old == event.path && now == Some(stamp) {
		return Ok(matches!(event.kind, FsEventKind::Remove));
	}
	let root = store.root().to_owned();
	let Some(path) = tokio::task::spawn_blocking(move || locate(&root, stamp)).await?? else {
		return Ok(false);
	};
	if old == path || (event.path != old && event.path != path) {
		return Ok(false);
	}
	let cache = context.volume_index();
	if !cache
		.store_for(&path)
		.await
		.is_some_and(|s| Arc::ptr_eq(&s, store))
		|| cache.watched_root_for_change(&path).await.is_none()
		|| should_filter_path(&path, rules, store.root(), None).await?
	{
		return Ok(false);
	}
	let Some(to) = tokio::task::spawn_blocking(move || verify(path, stamp)).await?? else {
		return Ok(false);
	};
	let arrives = event.path == to.path;
	tracing::debug!(from=%old.display(),to=%to.path.display(),"verified live APFS move");
	writer.apply(Seen::Renamed { from: old, to }).await;
	Ok(arrives || matches!(event.kind, FsEventKind::Remove))
}
