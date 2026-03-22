use crate::storage::{self, DirEntry, DnfsStorage, StorageError};
use crate::dns::DnsError;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyWrite,
    Request,
};
use libc::{EFBIG, EIO, ENOENT, ENOTEMPTY, EPERM};
use log::{debug, error, info};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 512;

fn system_time_from_epoch(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn make_attr(ino: u64, size: u64, kind: FileType, mode: u32, times: (u64, u64)) -> FileAttr {
    FileAttr {
        ino,
        size,
        blocks: (size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64,
        atime: system_time_from_epoch(times.1),
        mtime: system_time_from_epoch(times.1),
        ctime: system_time_from_epoch(times.0),
        crtime: system_time_from_epoch(times.0),
        kind,
        perm: mode as u16,
        nlink: if kind == FileType::Directory { 2 } else { 1 },
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

/// Track open file handles with reference counting
struct OpenFile {
    /// Number of open handles to this inode
    open_count: u32,
    /// Cached read data (populated on first read)
    read_cache: Option<Vec<u8>>,
}

pub struct DnfsFilesystem {
    store: DnfsStorage,
    writable: bool,
    /// Open file handle tracking (inode → state)
    open_files: HashMap<u64, OpenFile>,
    /// Write buffers (inode → pending data)
    write_buffers: HashMap<u64, Vec<u8>>,
    /// Next file handle ID
    next_fh: u64,
    /// Map file handle → inode for validation
    fh_to_ino: HashMap<u64, u64>,
}

impl DnfsFilesystem {
    pub fn new(mut store: DnfsStorage, writable: bool) -> Self {
        store.register_path("/");
        Self {
            store,
            writable,
            open_files: HashMap::new(),
            write_buffers: HashMap::new(),
            next_fh: 1,
            fh_to_ino: HashMap::new(),
        }
    }

    fn alloc_fh(&mut self, ino: u64) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.fh_to_ino.insert(fh, ino);
        fh
    }

    fn resolve_parent_path(&self, parent: u64) -> Option<String> {
        if parent == 1 {
            Some("/".to_string())
        } else {
            self.store.get_path(parent).map(|p| p.to_string())
        }
    }

    fn child_path(parent_path: &str, name: &str) -> String {
        if parent_path == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path, name)
        }
    }

    /// Map StorageError to errno
    fn storage_err_to_errno(e: &StorageError) -> i32 {
        match e {
            StorageError::NotFound(_) => ENOENT,
            StorageError::FileTooLarge { .. } => EFBIG,
            StorageError::CorruptRecord { .. } => EIO,
            StorageError::Dns(DnsError::RateLimited) => libc::EAGAIN,
            _ => EIO,
        }
    }
}

impl Filesystem for DnfsFilesystem {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(n) => n,
            None => { reply.error(ENOENT); return; }
        };

        let parent_path = match self.resolve_parent_path(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let child_path = Self::child_path(&parent_path, name_str);
        debug!("lookup: {} in parent={}", child_path, parent);

        // Try file
        if let Ok(meta) = self.store.stat_file(&child_path) {
            let ino = self.store.register_path(&child_path);
            reply.entry(&TTL, &make_attr(ino, meta.size, FileType::RegularFile, meta.mode, (meta.created, meta.modified)), 0);
            return;
        }

        // Try directory
        if let Ok(dm) = self.store.read_dir(&child_path) {
            if !dm.entries.is_empty() || {
                // Check if it was explicitly created (has a dir record)
                // read_dir returns empty for nonexistent dirs too, so check parent listing
                match self.store.read_dir(&parent_path) {
                    Ok(pd) => pd.entries.iter().any(|e| e.name == name_str && e.is_dir),
                    Err(_) => false,
                }
            } {
                let ino = self.store.register_path(&child_path);
                reply.entry(&TTL, &make_attr(ino, 0, FileType::Directory, 0o755, (dm.modified, dm.modified)), 0);
                return;
            }
        }

        reply.error(ENOENT);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == 1 {
            reply.attr(&TTL, &make_attr(1, 0, FileType::Directory, 0o755, (0, 0)));
            return;
        }

        let path = match self.store.get_path(ino) {
            Some(p) => p.to_string(),
            None => { reply.error(ENOENT); return; }
        };

        if let Ok(meta) = self.store.stat_file(&path) {
            reply.attr(&TTL, &make_attr(ino, meta.size, FileType::RegularFile, meta.mode, (meta.created, meta.modified)));
        } else if let Ok(dm) = self.store.read_dir(&path) {
            reply.attr(&TTL, &make_attr(ino, 0, FileType::Directory, 0o755, (dm.modified, dm.modified)));
        } else {
            reply.error(ENOENT);
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        let entry = self.open_files.entry(ino).or_insert(OpenFile {
            open_count: 0,
            read_cache: None,
        });
        entry.open_count += 1;
        let count = entry.open_count;

        let fh = self.alloc_fh(ino);
        debug!("open: ino={} fh={} count={}", ino, fh, count);
        reply.opened(fh, 0);
    }

    fn release(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        self.fh_to_ino.remove(&fh);

        let should_flush;
        let should_evict;

        if let Some(entry) = self.open_files.get_mut(&ino) {
            entry.open_count = entry.open_count.saturating_sub(1);
            should_flush = entry.open_count == 0 && self.write_buffers.contains_key(&ino);
            should_evict = entry.open_count == 0;
        } else {
            should_flush = self.write_buffers.contains_key(&ino);
            should_evict = false;
        }

        debug!("release: ino={} fh={} flush={} evict={}", ino, fh, should_flush, should_evict);

        // Flush pending writes on final close
        if should_flush {
            if let Some(data) = self.write_buffers.remove(&ino) {
                if let Some(path) = self.store.get_path(ino).map(|p| p.to_string()) {
                    match self.store.write_file(&path, &data) {
                        Ok(_) => info!("Flushed {} on release", path),
                        Err(e) => error!("Flush error on release {}: {}", path, e),
                    }
                }
            }
        }

        // Evict read cache on final close
        if should_evict {
            self.open_files.remove(&ino);
        }

        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let path = match self.store.get_path(ino) {
            Some(p) => p.to_string(),
            None => { reply.error(ENOENT); return; }
        };

        debug!("read: ino={} offset={} size={}", ino, offset, size);

        // Check open file cache
        let data = if let Some(of) = self.open_files.get(&ino) {
            if let Some(ref cached) = of.read_cache {
                cached.clone()
            } else {
                match self.store.read_file(&path) {
                    Ok(d) => {
                        if let Some(of) = self.open_files.get_mut(&ino) {
                            of.read_cache = Some(d.clone());
                        }
                        d
                    }
                    Err(e) => {
                        error!("read error {}: {}", path, e);
                        reply.error(Self::storage_err_to_errno(&e));
                        return;
                    }
                }
            }
        } else {
            match self.store.read_file(&path) {
                Ok(d) => d,
                Err(e) => {
                    error!("read error {}: {}", path, e);
                    reply.error(Self::storage_err_to_errno(&e));
                    return;
                }
            }
        };

        let offset = offset as usize;
        if offset >= data.len() {
            reply.data(&[]);
        } else {
            let end = (offset + size as usize).min(data.len());
            reply.data(&data[offset..end]);
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if !self.writable {
            reply.error(EPERM);
            return;
        }

        // Check file size limit before buffering
        let max_size = self.store.config().max_file_size;
        let new_end = offset as usize + data.len();
        if new_end > max_size {
            reply.error(EFBIG);
            return;
        }

        let buf = self.write_buffers.entry(ino).or_insert_with(Vec::new);
        let offset = offset as usize;

        if offset > buf.len() {
            buf.resize(offset, 0);
        }
        if offset + data.len() > buf.len() {
            buf.resize(offset + data.len(), 0);
        }
        buf[offset..offset + data.len()].copy_from_slice(data);

        reply.written(data.len() as u32);
    }

    fn flush(&mut self, _req: &Request, ino: u64, _fh: u64, _lock_owner: u64, reply: fuser::ReplyEmpty) {
        if let Some(data) = self.write_buffers.remove(&ino) {
            if let Some(path) = self.store.get_path(ino).map(|p| p.to_string()) {
                match self.store.write_file(&path, &data) {
                    Ok(_) => {
                        // Invalidate read cache
                        if let Some(of) = self.open_files.get_mut(&ino) {
                            of.read_cache = Some(data);
                        }
                        info!("Flushed {} to DNS", path);
                    }
                    Err(e) => {
                        error!("Flush error {}: {}", path, e);
                        // Put data back so it's not lost
                        self.write_buffers.insert(ino, data);
                        reply.error(Self::storage_err_to_errno(&e));
                        return;
                    }
                }
            }
        }
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = if ino == 1 {
            "/".to_string()
        } else {
            match self.store.get_path(ino) {
                Some(p) => p.to_string(),
                None => { reply.error(ENOENT); return; }
            }
        };

        let dir_meta = match self.store.read_dir(&path) {
            Ok(m) => m,
            Err(e) => {
                if offset == 0 {
                    let _ = reply.add(ino, 1, FileType::Directory, ".");
                    let _ = reply.add(ino, 2, FileType::Directory, "..");
                }
                reply.ok();
                return;
            }
        };

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (ino, FileType::Directory, "..".to_string()),
        ];

        for entry in &dir_meta.entries {
            let child_path = Self::child_path(&path, &entry.name);
            let child_ino = self.store.register_path(&child_path);
            let ftype = if entry.is_dir { FileType::Directory } else { FileType::RegularFile };
            entries.push((child_ino, ftype, entry.name.clone()));
        }

        for (i, (ino, ftype, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *ftype, name) {
                break;
            }
        }
        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        if !self.writable { reply.error(EPERM); return; }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => { reply.error(ENOENT); return; }
        };

        let parent_path = match self.resolve_parent_path(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let child_path = Self::child_path(&parent_path, name_str);
        info!("create: {}", child_path);

        match self.store.write_file(&child_path, &[]) {
            Ok(meta) => {
                let ino = self.store.register_path(&child_path);

                let mut dir = self.store.read_dir(&parent_path).unwrap_or(storage::DirMeta {
                    entries: vec![], modified: 0,
                });
                if !dir.entries.iter().any(|e| e.name == name_str) {
                    dir.entries.push(DirEntry { name: name_str.to_string(), is_dir: false, inode: ino });
                    let _ = self.store.write_dir(&parent_path, &dir.entries);
                }

                // Auto-open with file handle
                let fh = self.alloc_fh(ino);
                self.open_files.insert(ino, OpenFile { open_count: 1, read_cache: None });

                reply.created(&TTL, &make_attr(ino, 0, FileType::RegularFile, 0o644, (meta.created, meta.modified)), 0, fh, 0);
            }
            Err(e) => {
                error!("create error: {}", e);
                reply.error(Self::storage_err_to_errno(&e));
            }
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if !self.writable { reply.error(EPERM); return; }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => { reply.error(ENOENT); return; }
        };

        let parent_path = match self.resolve_parent_path(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let child_path = Self::child_path(&parent_path, name_str);
        info!("mkdir: {}", child_path);

        match self.store.write_dir(&child_path, &[]) {
            Ok(()) => {
                let ino = self.store.register_path(&child_path);

                let mut dir = self.store.read_dir(&parent_path).unwrap_or(storage::DirMeta {
                    entries: vec![], modified: 0,
                });
                dir.entries.push(DirEntry { name: name_str.to_string(), is_dir: true, inode: ino });
                let _ = self.store.write_dir(&parent_path, &dir.entries);

                let now = now_epoch();
                reply.entry(&TTL, &make_attr(ino, 0, FileType::Directory, 0o755, (now, now)), 0);
            }
            Err(e) => {
                error!("mkdir error: {}", e);
                reply.error(EIO);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        if !self.writable { reply.error(EPERM); return; }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => { reply.error(ENOENT); return; }
        };

        let parent_path = match self.resolve_parent_path(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let child_path = Self::child_path(&parent_path, name_str);
        info!("unlink: {}", child_path);

        // Capture inode BEFORE delete_file removes it from path_map
        let child_ino = self.store.get_inode(&child_path);

        match self.store.delete_file(&child_path) {
            Ok(()) => {
                if let Ok(mut dir) = self.store.read_dir(&parent_path) {
                    dir.entries.retain(|e| e.name != name_str);
                    let _ = self.store.write_dir(&parent_path, &dir.entries);
                }
                // Clean up any open handles using the inode we captured above
                if let Some(ino) = child_ino {
                    self.open_files.remove(&ino);
                    self.write_buffers.remove(&ino);
                }
                reply.ok();
            }
            Err(e) => {
                error!("unlink error: {}", e);
                reply.error(Self::storage_err_to_errno(&e));
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        if !self.writable { reply.error(EPERM); return; }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => { reply.error(ENOENT); return; }
        };

        let parent_path = match self.resolve_parent_path(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let child_path = Self::child_path(&parent_path, name_str);

        // Check if directory is empty
        if let Ok(dm) = self.store.read_dir(&child_path) {
            if !dm.entries.is_empty() {
                reply.error(ENOTEMPTY);
                return;
            }
        }

        // Remove dir record
        let _ = self.store.delete_file(&child_path);

        // Update parent
        if let Ok(mut dir) = self.store.read_dir(&parent_path) {
            dir.entries.retain(|e| e.name != name_str);
            let _ = self.store.write_dir(&parent_path, &dir.entries);
        }

        reply.ok();
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        if !self.writable { reply.error(EPERM); return; }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => { reply.error(ENOENT); return; }
        };
        let newname_str = match newname.to_str() {
            Some(n) => n,
            None => { reply.error(ENOENT); return; }
        };

        let old_parent_path = match self.resolve_parent_path(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };
        let new_parent_path = match self.resolve_parent_path(newparent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let old_path = Self::child_path(&old_parent_path, name_str);
        let new_path = Self::child_path(&new_parent_path, newname_str);

        info!("rename: {} → {}", old_path, new_path);

        // Determine if it's a file or directory
        let is_dir = self.store.stat_file(&old_path).is_err();

        if is_dir {
            // For directories: rename the dir record
            match self.store.read_dir(&old_path) {
                Ok(dm) => {
                    let _ = self.store.write_dir(&new_path, &dm.entries);
                    let _ = self.store.delete_file(&old_path);
                }
                Err(e) => {
                    error!("rename dir error: {}", e);
                    reply.error(EIO);
                    return;
                }
            }
        } else {
            // For files: read → write new → delete old (dedup keeps chunks)
            match self.store.rename_file(&old_path, &new_path) {
                Ok(()) => {}
                Err(e) => {
                    error!("rename error: {}", e);
                    reply.error(Self::storage_err_to_errno(&e));
                    return;
                }
            }
        }

        // Update old parent directory
        if let Ok(mut dir) = self.store.read_dir(&old_parent_path) {
            dir.entries.retain(|e| e.name != name_str);
            let _ = self.store.write_dir(&old_parent_path, &dir.entries);
        }

        // Update new parent directory
        let ino = self.store.register_path(&new_path);
        if let Ok(mut dir) = self.store.read_dir(&new_parent_path) {
            dir.entries.retain(|e| e.name != newname_str); // Remove existing if overwrite
            dir.entries.push(DirEntry {
                name: newname_str.to_string(),
                is_dir,
                inode: ino,
            });
            let _ = self.store.write_dir(&new_parent_path, &dir.entries);
        }

        reply.ok();
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Handle truncate (size=0 on open with O_TRUNC)
        if let Some(new_size) = size {
            if new_size == 0 {
                if let Some(path) = self.store.get_path(ino).map(|p| p.to_string()) {
                    let _ = self.store.write_file(&path, &[]);
                    // Clear write buffer too
                    self.write_buffers.remove(&ino);
                    if let Some(of) = self.open_files.get_mut(&ino) {
                        of.read_cache = None;
                    }
                }
            }
        }

        // Return current attrs
        self.getattr(_req, ino, None, reply);
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
