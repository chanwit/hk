//! Ext4 Filesystem Implementation (Read-only)
//!
//! Read-only ext4 driver for mounting ext4 filesystems on block devices.
//!
//! ## Features
//! - Ext4 filesystem support (read-only)
//! - Extent tree support for file block mapping
//! - Directory iteration (linear and htree)
//! - Large file support (>2GB)
//!
//! ## On-Disk Format
//! Ext4 uses:
//! - Superblock at offset 1024 with filesystem metadata
//! - Block group descriptor table for organizing blocks into groups
//! - Extent trees for efficient block mapping (replaces indirect blocks)
//! - Directory entries with file type and variable length names

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use spin::RwLock;

use crate::frame_alloc::FrameAllocRef;
use crate::mm::page_cache::{AddressSpaceOps, FileId, PAGE_SIZE};
use crate::storage::{BlockDevice, DevId, get_blkdev};
use crate::{FRAME_ALLOCATOR, PAGE_CACHE};

use super::dentry::Dentry;
use super::file::{DirEntry as VfsDirEntry, File, FileOps};
use super::inode::{AsAny, FileType, Inode, InodeData, InodeMode, InodeOps, Timespec};
use super::superblock::{FileSystemType, SuperBlock, SuperBlockData, SuperOps};
use super::vfs::FsError;

// ============================================================================
// Ext4 Constants
// ============================================================================

/// Ext4 superblock magic number
const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Ext4 superblock offset (1024 bytes from start)
const EXT4_SUPER_OFFSET: u64 = 1024;

/// Default block size (typically 4096)
const DEFAULT_BLOCK_SIZE: u32 = 4096;

/// Root inode number
const EXT4_ROOT_INO: u32 = 2;

/// Extent header magic
const EXT4_EXT_MAGIC: u16 = 0xF30A;

// Inode flags
const EXT4_EXTENTS_FL: u32 = 0x00080000; // Inode uses extents

// Feature flags - incompatible features that prevent read-only mounting
const EXT4_FEATURE_INCOMPAT_COMPRESSION: u32 = 0x0001; // Compression
const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;    // Directory entries have file type
const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;     // Journal recovery needed
const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008; // Journal on separate device
const EXT4_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;     // Meta block groups
const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;     // Extents support
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;       // 64-bit support
const EXT4_FEATURE_INCOMPAT_MMP: u32 = 0x0100;         // Multi-mount protection
const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;     // Flexible block groups
const EXT4_FEATURE_INCOMPAT_EA_INODE: u32 = 0x0400;    // Extended attributes in inode
const EXT4_FEATURE_INCOMPAT_DIRDATA: u32 = 0x1000;     // Data in directory entries
const EXT4_FEATURE_INCOMPAT_CSUM_SEED: u32 = 0x2000;   // Metadata checksum seed
const EXT4_FEATURE_INCOMPAT_LARGEDIR: u32 = 0x4000;    // Large directories (>2GB)
const EXT4_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000; // Inline data in inode
const EXT4_FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;    // Encryption

// File type in directory entries
const EXT4_FT_UNKNOWN: u8 = 0;
const EXT4_FT_REG_FILE: u8 = 1;
const EXT4_FT_DIR: u8 = 2;
const EXT4_FT_CHRDEV: u8 = 3;
const EXT4_FT_BLKDEV: u8 = 4;
const EXT4_FT_FIFO: u8 = 5;
const EXT4_FT_SOCK: u8 = 6;
const EXT4_FT_SYMLINK: u8 = 7;

// ============================================================================
// Ext4 AddressSpaceOps - Page I/O
// ============================================================================

/// Ext4 address space operations for page cache
pub struct Ext4AddressSpaceOps;

impl AddressSpaceOps for Ext4AddressSpaceOps {
    fn readpage(&self, file_id: FileId, page_offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        // Decode FileId to get block device
        let (major, minor) = file_id.to_blkdev().ok_or(-5)?; // EIO
        let bdev = get_blkdev(DevId::new(major, minor)).ok_or(-5)?;

        // Read from block device
        bdev.disk
            .queue
            .driver()
            .readpage(&bdev.disk, buf, page_offset);

        Ok(PAGE_SIZE)
    }

    fn writepage(&self, _file_id: FileId, _page_offset: u64, _buf: &[u8]) -> Result<usize, i32> {
        // Read-only filesystem
        Err(-30) // EROFS
    }
}

/// Global ext4 address space ops instance
pub static EXT4_AOPS: Ext4AddressSpaceOps = Ext4AddressSpaceOps;

// ============================================================================
// Ext4 On-Disk Structures
// ============================================================================

/// Ext4 Superblock (first 1024 bytes contain boot sector, superblock at +1024)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Superblock {
    pub s_inodes_count: u32,        // Total inode count
    pub s_blocks_count_lo: u32,     // Total block count (low 32 bits)
    pub s_r_blocks_count_lo: u32,   // Reserved block count (low)
    pub s_free_blocks_count_lo: u32, // Free block count (low)
    pub s_free_inodes_count: u32,   // Free inode count
    pub s_first_data_block: u32,    // First data block
    pub s_log_block_size: u32,      // Block size = 1024 << s_log_block_size
    pub s_log_cluster_size: u32,    // Cluster size
    pub s_blocks_per_group: u32,    // Blocks per group
    pub s_clusters_per_group: u32,  // Clusters per group
    pub s_inodes_per_group: u32,    // Inodes per group
    pub s_mtime: u32,               // Mount time
    pub s_wtime: u32,               // Write time
    pub s_mnt_count: u16,           // Mount count
    pub s_max_mnt_count: u16,       // Max mount count
    pub s_magic: u16,               // Magic signature (0xEF53)
    pub s_state: u16,               // File system state
    pub s_errors: u16,              // Behavior on errors
    pub s_minor_rev_level: u16,     // Minor revision level
    pub s_lastcheck: u32,           // Last check time
    pub s_checkinterval: u32,       // Check interval
    pub s_creator_os: u32,          // Creator OS
    pub s_rev_level: u32,           // Revision level
    pub s_def_resuid: u16,          // Default reserved user ID
    pub s_def_resgid: u16,          // Default reserved group ID
    // EXT4_DYNAMIC_REV specific
    pub s_first_ino: u32,           // First non-reserved inode
    pub s_inode_size: u16,          // Inode size
    pub s_block_group_nr: u16,      // Block group number of this superblock
    pub s_feature_compat: u32,      // Compatible features
    pub s_feature_incompat: u32,    // Incompatible features
    pub s_feature_ro_compat: u32,   // Read-only compatible features
    pub s_uuid: [u8; 16],           // Volume UUID
    pub s_volume_name: [u8; 16],    // Volume name
    pub s_last_mounted: [u8; 64],   // Last mount point
    pub s_algorithm_usage_bitmap: u32, // Compression algorithm
    pub s_prealloc_blocks: u8,      // Blocks to preallocate
    pub s_prealloc_dir_blocks: u8,  // Dir blocks to preallocate
    pub s_reserved_gdt_blocks: u16, // Reserved GDT blocks
    pub s_journal_uuid: [u8; 16],   // Journal UUID
    pub s_journal_inum: u32,        // Journal inode number
    pub s_journal_dev: u32,         // Journal device
    pub s_last_orphan: u32,         // Head of orphan inode list
    pub s_hash_seed: [u32; 4],      // Hash seed
    pub s_def_hash_version: u8,     // Default hash version
    pub s_jnl_backup_type: u8,      // Journal backup type
    pub s_desc_size: u16,           // Group descriptor size
    pub s_default_mount_opts: u32,  // Default mount options
    pub s_first_meta_bg: u32,       // First metablock group
    pub s_mkfs_time: u32,           // Filesystem creation time
    pub s_jnl_blocks: [u32; 17],    // Journal backup
    // 64-bit support
    pub s_blocks_count_hi: u32,     // Total block count (high 32 bits)
    pub s_r_blocks_count_hi: u32,   // Reserved block count (high)
    pub s_free_blocks_count_hi: u32, // Free block count (high)
    pub s_min_extra_isize: u16,     // Min extra inode size
    pub s_want_extra_isize: u16,    // Wanted extra inode size
    pub s_flags: u32,               // Misc flags
    pub s_raid_stride: u16,         // RAID stride
    pub s_mmp_interval: u16,        // Multi-mount protection interval
    pub s_mmp_block: u64,           // Multi-mount protection block
    pub s_raid_stripe_width: u32,   // RAID stripe width
    pub s_log_groups_per_flex: u8,  // Flexible block group size
    pub s_checksum_type: u8,        // Metadata checksum algorithm
    pub s_reserved_pad: u16,
    pub s_kbytes_written: u64,      // KB written
    pub s_snapshot_inum: u32,       // Snapshot inode
    pub s_snapshot_id: u32,         // Snapshot ID
    pub s_snapshot_r_blocks_count: u64, // Snapshot reserved blocks
    pub s_snapshot_list: u32,       // Snapshot list inode
    pub s_error_count: u32,         // Error count
    pub s_first_error_time: u32,    // First error time
    pub s_first_error_ino: u32,     // First error inode
    pub s_first_error_block: u64,   // First error block
    pub s_first_error_func: [u8; 32], // First error function
    pub s_first_error_line: u32,    // First error line
    pub s_last_error_time: u32,     // Last error time
    pub s_last_error_ino: u32,      // Last error inode
    pub s_last_error_line: u32,     // Last error line
    pub s_last_error_block: u64,    // Last error block
    pub s_last_error_func: [u8; 32], // Last error function
    pub s_mount_opts: [u8; 64],     // Mount options
    pub s_usr_quota_inum: u32,      // User quota inode
    pub s_grp_quota_inum: u32,      // Group quota inode
    pub s_overhead_blocks: u32,     // Overhead blocks
    pub s_backup_bgs: [u32; 2],     // Backup block groups
    pub s_encrypt_algos: [u8; 4],   // Encryption algorithms
    pub s_encrypt_pw_salt: [u8; 16], // Encryption password salt
    pub s_lpf_ino: u32,             // Lost+found inode
    pub s_prj_quota_inum: u32,      // Project quota inode
    pub s_checksum_seed: u32,       // Checksum seed
    pub s_reserved: [u32; 98],      // Padding to 1024 bytes
    pub s_checksum: u32,            // Superblock checksum
}

/// Ext4 Block Group Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4GroupDesc {
    pub bg_block_bitmap_lo: u32,      // Block bitmap block (low)
    pub bg_inode_bitmap_lo: u32,      // Inode bitmap block (low)
    pub bg_inode_table_lo: u32,       // Inode table block (low)
    pub bg_free_blocks_count_lo: u16, // Free blocks count (low)
    pub bg_free_inodes_count_lo: u16, // Free inodes count (low)
    pub bg_used_dirs_count_lo: u16,   // Used directories count (low)
    pub bg_flags: u16,                // Flags
    pub bg_exclude_bitmap_lo: u32,    // Exclude bitmap (low)
    pub bg_block_bitmap_csum_lo: u16, // Block bitmap checksum (low)
    pub bg_inode_bitmap_csum_lo: u16, // Inode bitmap checksum (low)
    pub bg_itable_unused_lo: u16,     // Unused inode count (low)
    pub bg_checksum: u16,             // Group descriptor checksum
    // 64-bit fields (if desc_size > 32)
    pub bg_block_bitmap_hi: u32,      // Block bitmap block (high)
    pub bg_inode_bitmap_hi: u32,      // Inode bitmap block (high)
    pub bg_inode_table_hi: u32,       // Inode table block (high)
    pub bg_free_blocks_count_hi: u16, // Free blocks count (high)
    pub bg_free_inodes_count_hi: u16, // Free inodes count (high)
    pub bg_used_dirs_count_hi: u16,   // Used directories count (high)
    pub bg_itable_unused_hi: u16,     // Unused inode count (high)
    pub bg_exclude_bitmap_hi: u32,    // Exclude bitmap (high)
    pub bg_block_bitmap_csum_hi: u16, // Block bitmap checksum (high)
    pub bg_inode_bitmap_csum_hi: u16, // Inode bitmap checksum (high)
    pub bg_reserved: u32,             // Padding
}

/// Ext4 Inode (256 bytes typical)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Inode {
    pub i_mode: u16,           // File mode
    pub i_uid: u16,            // Owner UID (low)
    pub i_size_lo: u32,        // File size (low)
    pub i_atime: u32,          // Access time
    pub i_ctime: u32,          // Change time
    pub i_mtime: u32,          // Modification time
    pub i_dtime: u32,          // Deletion time
    pub i_gid: u16,            // Group ID (low)
    pub i_links_count: u16,    // Hard link count
    pub i_blocks_lo: u32,      // Block count (low)
    pub i_flags: u32,          // Flags
    pub i_osd1: u32,           // OS-dependent 1
    pub i_block: [u32; 15],    // Block pointers / extent tree
    pub i_generation: u32,     // File version (NFS)
    pub i_file_acl_lo: u32,    // Extended attributes block (low)
    pub i_size_high: u32,      // File size (high)
    pub i_obso_faddr: u32,     // Obsolete fragment address
    pub i_osd2: [u8; 12],      // OS-dependent 2
    pub i_extra_isize: u16,    // Extra inode size
    pub i_checksum_hi: u16,    // Inode checksum (high)
    pub i_ctime_extra: u32,    // Extra change time
    pub i_mtime_extra: u32,    // Extra modification time
    pub i_atime_extra: u32,    // Extra access time
    pub i_crtime: u32,         // Creation time
    pub i_crtime_extra: u32,   // Extra creation time
    pub i_version_hi: u32,     // Version (high)
    pub i_projid: u32,         // Project ID
}

/// Ext4 Extent Header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentHeader {
    pub eh_magic: u16,      // Magic number (0xF30A)
    pub eh_entries: u16,    // Number of valid entries
    pub eh_max: u16,        // Capacity of entries
    pub eh_depth: u16,      // Depth of extent tree (0 = leaf)
    pub eh_generation: u32, // Generation
}

/// Ext4 Extent Index (internal node)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentIdx {
    pub ei_block: u32,  // Logical block covered
    pub ei_leaf_lo: u32, // Physical block of child (low)
    pub ei_leaf_hi: u16, // Physical block of child (high)
    pub ei_unused: u16,
}

/// Ext4 Extent (leaf node)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Extent {
    pub ee_block: u32,  // First logical block
    pub ee_len: u16,    // Number of blocks (max 32768)
    pub ee_start_hi: u16, // Physical block (high)
    pub ee_start_lo: u32, // Physical block (low)
}

/// Ext4 Directory Entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4DirEntry2 {
    pub inode: u32,      // Inode number
    pub rec_len: u16,    // Directory entry length
    pub name_len: u8,    // Name length
    pub file_type: u8,   // File type
    // name follows (variable length)
}

// ============================================================================
// Ext4 Filesystem State
// ============================================================================

/// Ext4 superblock data (stored in SuperBlock.private)
pub struct Ext4SbData {
    /// Underlying block device
    pub bdev: Arc<BlockDevice>,
    /// Block size (1024, 2048, 4096, etc.)
    pub block_size: u32,
    /// Inode size (typically 256)
    pub inode_size: u32,
    /// Inodes per group
    pub inodes_per_group: u32,
    /// Blocks per group
    pub blocks_per_group: u32,
    /// Total block groups
    pub group_count: u32,
    /// Group descriptor size
    pub desc_size: u32,
    /// First data block (0 for 2K+ blocks, 1 for 1K blocks)
    pub first_data_block: u32,
    /// Cached group descriptors
    pub group_descs: RwLock<Vec<Ext4GroupDesc>>,
    /// Inode cache (ino -> Ext4Inode)
    pub inode_cache: RwLock<BTreeMap<u32, Ext4Inode>>,
}

impl SuperBlockData for Ext4SbData {}

impl AsAny for Ext4SbData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Ext4 inode data (stored in Inode.private)
pub struct Ext4InodeData {
    /// Ext4 inode number
    pub ino: u32,
    /// Cached extent tree root (i_block[0..60])
    pub extent_data: [u8; 60],
}

impl InodeData for Ext4InodeData {}

impl AsAny for Ext4InodeData {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

// ============================================================================
// Block Device I/O Helpers
// ============================================================================

/// Read a block from the block device
fn read_block(bdev: &BlockDevice, block_num: u64, block_size: u32) -> Result<Vec<u8>, FsError> {
    let mut buf = alloc::vec![0u8; block_size as usize];
    read_bytes(bdev, block_num * block_size as u64, &mut buf)?;
    Ok(buf)
}

/// Read bytes from block device via page cache
fn read_bytes(bdev: &BlockDevice, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
    let file_id = FileId::from_blkdev(bdev.dev_id().major, bdev.dev_id().minor);
    let capacity = bdev.capacity();

    let mut pos = offset;
    let mut remaining = buf.len();
    let mut buf_offset = 0;

    while remaining > 0 {
        let page_offset = pos / PAGE_SIZE as u64;
        let offset_in_page = (pos % PAGE_SIZE as u64) as usize;
        let chunk_size = core::cmp::min(remaining, PAGE_SIZE - offset_in_page);

        let (frame, needs_read) = {
            let mut cache = PAGE_CACHE.lock();
            let mut frame_alloc = FrameAllocRef(&FRAME_ALLOCATOR);
            let (page, is_new) = cache
                .find_or_create_page(
                    file_id,
                    page_offset,
                    capacity,
                    &mut frame_alloc,
                    false, // ext4 read-only, no writeback
                    false,
                    &EXT4_AOPS,
                )
                .map_err(|_| FsError::IoError)?;
            (page.frame, is_new)
        };

        if needs_read {
            let page_buf = unsafe { core::slice::from_raw_parts_mut(frame as *mut u8, PAGE_SIZE) };
            bdev.disk
                .queue
                .driver()
                .readpage(&bdev.disk, page_buf, page_offset);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                (frame as *const u8).add(offset_in_page),
                buf.as_mut_ptr().add(buf_offset),
                chunk_size,
            );
        }

        pos += chunk_size as u64;
        buf_offset += chunk_size;
        remaining -= chunk_size;
    }

    Ok(())
}

// ============================================================================
// Ext4 Superblock Operations
// ============================================================================

impl Ext4SbData {
    /// Read and parse ext4 superblock
    fn read_superblock(bdev: &Arc<BlockDevice>) -> Result<(Ext4Superblock, Self), FsError> {
        // Read superblock at offset 1024
        let mut sb_buf = [0u8; size_of::<Ext4Superblock>()];
        read_bytes(bdev, EXT4_SUPER_OFFSET, &mut sb_buf)?;

        let sb: Ext4Superblock = unsafe { core::ptr::read_unaligned(sb_buf.as_ptr() as *const _) };

        // Validate magic
        if sb.s_magic != EXT4_SUPER_MAGIC {
            return Err(FsError::IoError);
        }

        // Check for incompatible features that we cannot support in read-only mode
        // Features we explicitly reject:
        // - COMPRESSION: Compressed files require special decompression
        // - ENCRYPT: Encrypted files require decryption keys
        // - INLINE_DATA: Data stored in inode i_block area instead of extent tree
        // - JOURNAL_DEV: Filesystem is a journal device, not a normal filesystem
        let unsupported_features = EXT4_FEATURE_INCOMPAT_COMPRESSION
            | EXT4_FEATURE_INCOMPAT_ENCRYPT
            | EXT4_FEATURE_INCOMPAT_INLINE_DATA
            | EXT4_FEATURE_INCOMPAT_JOURNAL_DEV;

        if sb.s_feature_incompat & unsupported_features != 0 {
            // Filesystem has features we cannot handle
            return Err(FsError::NotSupported);
        }

        // Features we can safely ignore for read-only:
        // - RECOVER: Journal needs recovery (safe to ignore when mounting read-only)
        // - FILETYPE: Directory entries have file type (we support this)
        // - EXTENTS: Extent tree support (we support this)
        // - 64BIT: 64-bit block numbers (we support this)
        // - META_BG, MMP, FLEX_BG, EA_INODE, DIRDATA, CSUM_SEED, LARGEDIR:
        //   All safe to ignore for read-only operations

        // Calculate block size
        let block_size = 1024u32 << sb.s_log_block_size;
        let inode_size = if sb.s_rev_level == 0 {
            128
        } else {
            sb.s_inode_size as u32
        };

        let desc_size = if sb.s_desc_size == 0 {
            32
        } else {
            sb.s_desc_size as u32
        };

        // Calculate total block groups
        let total_blocks = ((sb.s_blocks_count_hi as u64) << 32) | (sb.s_blocks_count_lo as u64);
        let group_count = ((total_blocks + sb.s_blocks_per_group as u64 - 1)
            / sb.s_blocks_per_group as u64) as u32;

        let sb_data = Self {
            bdev: bdev.clone(),
            block_size,
            inode_size,
            inodes_per_group: sb.s_inodes_per_group,
            blocks_per_group: sb.s_blocks_per_group,
            group_count,
            desc_size,
            first_data_block: sb.s_first_data_block,
            group_descs: RwLock::new(Vec::new()),
            inode_cache: RwLock::new(BTreeMap::new()),
        };

        Ok((sb, sb_data))
    }

    /// Load group descriptor table
    fn load_group_descs(&self, _sb: &Ext4Superblock) -> Result<(), FsError> {
        // Group descriptor table starts after superblock
        let gdt_block = self.first_data_block + 1;
        let descs_per_block = self.block_size / self.desc_size;

        let mut descs = Vec::new();

        for group in 0..self.group_count {
            let block_offset = group / descs_per_block;
            let desc_offset = (group % descs_per_block) * self.desc_size;

            let block_data = read_block(&self.bdev, gdt_block as u64 + block_offset as u64, self.block_size)?;

            let desc: Ext4GroupDesc = unsafe {
                core::ptr::read_unaligned(
                    block_data.as_ptr().add(desc_offset as usize) as *const _
                )
            };

            descs.push(desc);
        }

        *self.group_descs.write() = descs;
        Ok(())
    }

    /// Read an inode from disk
    fn read_inode(&self, ino: u32) -> Result<Ext4Inode, FsError> {
        // Check cache first
        {
            let cache = self.inode_cache.read();
            if let Some(inode) = cache.get(&ino) {
                return Ok(*inode);
            }
        }

        // Calculate group and index
        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;

        // Get group descriptor
        let group_descs = self.group_descs.read();
        let gd = group_descs.get(group as usize).ok_or(FsError::IoError)?;

        // Calculate inode table block
        let inode_table = ((gd.bg_inode_table_hi as u64) << 32) | (gd.bg_inode_table_lo as u64);
        let inode_block = inode_table + (index as u64 * self.inode_size as u64) / self.block_size as u64;
        let inode_offset = ((index * self.inode_size) % self.block_size) as usize;

        // Read block containing inode
        let block_data = read_block(&self.bdev, inode_block, self.block_size)?;

        let inode: Ext4Inode = unsafe {
            core::ptr::read_unaligned(block_data.as_ptr().add(inode_offset) as *const _)
        };

        // Cache it
        self.inode_cache.write().insert(ino, inode);

        Ok(inode)
    }

    /// Map logical block to physical block using extent tree
    fn extent_map_block(&self, inode: &Ext4Inode, logical_block: u64) -> Result<u64, FsError> {
        // Ensure inode uses extents
        if inode.i_flags & EXT4_EXTENTS_FL == 0 {
            return Err(FsError::NotSupported); // Old indirect blocks not supported
        }

        // Copy i_block to local array to avoid packed struct field reference
        let i_block: [u32; 15] = unsafe {
            let ptr = core::ptr::addr_of!(inode.i_block);
            core::ptr::read_unaligned(ptr)
        };

        // Parse extent header from i_block
        let extent_data = unsafe {
            core::slice::from_raw_parts(
                i_block.as_ptr() as *const u8,
                60, // 15 * 4 bytes
            )
        };

        self.extent_tree_search(extent_data, logical_block)
    }

    /// Search extent tree recursively
    fn extent_tree_search(&self, extent_data: &[u8], logical_block: u64) -> Result<u64, FsError> {
        // Read extent header
        let header: Ext4ExtentHeader = unsafe {
            core::ptr::read_unaligned(extent_data.as_ptr() as *const _)
        };

        if header.eh_magic != EXT4_EXT_MAGIC {
            return Err(FsError::IoError);
        }

        let entries = header.eh_entries as usize;
        let depth = header.eh_depth;

        if depth == 0 {
            // Leaf node - search extents
            let extents_offset = size_of::<Ext4ExtentHeader>();
            for i in 0..entries {
                let extent_offset = extents_offset + i * size_of::<Ext4Extent>();
                let extent: Ext4Extent = unsafe {
                    core::ptr::read_unaligned(
                        extent_data.as_ptr().add(extent_offset) as *const _
                    )
                };

                let start_block = extent.ee_block as u64;
                let len = (extent.ee_len & 0x7FFF) as u64; // Clear unwritten flag

                if logical_block >= start_block && logical_block < start_block + len {
                    // Found the extent
                    let phys_start = ((extent.ee_start_hi as u64) << 32) | (extent.ee_start_lo as u64);
                    return Ok(phys_start + (logical_block - start_block));
                }
            }

            Err(FsError::NotFound) // Block not mapped (sparse file)
        } else {
            // Internal node - search indices
            let indices_offset = size_of::<Ext4ExtentHeader>();
            for i in 0..entries {
                let idx_offset = indices_offset + i * size_of::<Ext4ExtentIdx>();
                let idx: Ext4ExtentIdx = unsafe {
                    core::ptr::read_unaligned(
                        extent_data.as_ptr().add(idx_offset) as *const _
                    )
                };

                // Check if this index covers our block
                let next_idx_block = if i + 1 < entries {
                    let next_idx: Ext4ExtentIdx = unsafe {
                        core::ptr::read_unaligned(
                            extent_data.as_ptr().add(idx_offset + size_of::<Ext4ExtentIdx>()) as *const _
                        )
                    };
                    next_idx.ei_block as u64
                } else {
                    u64::MAX
                };

                if logical_block >= idx.ei_block as u64 && logical_block < next_idx_block {
                    // Follow this index
                    let child_block = ((idx.ei_leaf_hi as u64) << 32) | (idx.ei_leaf_lo as u64);
                    let child_data = read_block(&self.bdev, child_block, self.block_size)?;
                    return self.extent_tree_search(&child_data, logical_block);
                }
            }

            Err(FsError::NotFound)
        }
    }
}

// ============================================================================
// Ext4 Inode Operations
// ============================================================================

pub struct Ext4InodeOps;

impl InodeOps for Ext4InodeOps {
    fn lookup(&self, dir: &Inode, name: &str) -> Result<Arc<Inode>, FsError> {
        // Get ext4 inode data
        let private = dir.get_private().ok_or(FsError::IoError)?;
        let ext4_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4InodeData>()
            .ok_or(FsError::IoError)?;

        let sb = dir.superblock().ok_or(FsError::IoError)?;
        let sb_private = sb.get_private().ok_or(FsError::IoError)?;
        let sb_data = sb_private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4SbData>()
            .ok_or(FsError::IoError)?;

        // Read ext4 inode
        let ext4_inode = sb_data.read_inode(ext4_data.ino)?;

        // Read directory blocks
        let file_size = ((ext4_inode.i_size_high as u64) << 32) | (ext4_inode.i_size_lo as u64);
        let num_blocks = (file_size + sb_data.block_size as u64 - 1) / sb_data.block_size as u64;

        for block_idx in 0..num_blocks {
            let phys_block = sb_data.extent_map_block(&ext4_inode, block_idx)?;
            let block_data = read_block(&sb_data.bdev, phys_block, sb_data.block_size)?;

            // Parse directory entries
            let mut offset = 0;
            while offset < block_data.len() {
                let entry: Ext4DirEntry2 = unsafe {
                    core::ptr::read_unaligned(block_data.as_ptr().add(offset) as *const _)
                };

                if entry.inode == 0 || entry.rec_len == 0 {
                    break;
                }

                // Extract name
                let name_bytes = &block_data[offset + size_of::<Ext4DirEntry2>()..offset + size_of::<Ext4DirEntry2>() + entry.name_len as usize];
                if let Ok(entry_name) = core::str::from_utf8(name_bytes) {
                    if entry_name == name {
                        // Found it - create VFS inode
                        return create_vfs_inode(&sb, sb_data, entry.inode);
                    }
                }

                offset += entry.rec_len as usize;
            }
        }

        Err(FsError::NotFound)
    }

    fn readpage(&self, inode: &Inode, page_offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ext4_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4InodeData>()
            .ok_or(FsError::IoError)?;

        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_private = sb.get_private().ok_or(FsError::IoError)?;
        let sb_data = sb_private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4SbData>()
            .ok_or(FsError::IoError)?;

        let ext4_inode = sb_data.read_inode(ext4_data.ino)?;

        // Calculate logical block
        let logical_block = (page_offset * PAGE_SIZE as u64) / sb_data.block_size as u64;

        // Map to physical block
        let phys_block = sb_data.extent_map_block(&ext4_inode, logical_block)?;

        // Read the block
        let block_data = read_block(&sb_data.bdev, phys_block, sb_data.block_size)?;

        // Copy to buffer
        let copy_len = core::cmp::min(buf.len(), block_data.len());
        buf[..copy_len].copy_from_slice(&block_data[..copy_len]);

        Ok(copy_len)
    }
}

pub static EXT4_INODE_OPS: Ext4InodeOps = Ext4InodeOps;

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert ext4 file type to VFS FileType
fn ext4_file_type_to_vfs(ft: u8) -> FileType {
    match ft {
        EXT4_FT_REG_FILE => FileType::Regular,
        EXT4_FT_DIR => FileType::Directory,
        EXT4_FT_SYMLINK => FileType::Symlink,
        EXT4_FT_CHRDEV => FileType::CharDev,
        EXT4_FT_BLKDEV => FileType::BlockDev,
        EXT4_FT_FIFO => FileType::Fifo,
        EXT4_FT_SOCK => FileType::Socket,
        _ => FileType::Regular,
    }
}

/// Convert ext4 inode mode to VFS InodeMode
fn ext4_mode_to_vfs(mode: u16) -> InodeMode {
    InodeMode(mode)
}

/// Create VFS inode from ext4 inode
fn create_vfs_inode(
    sb: &Arc<SuperBlock>,
    sb_data: &Ext4SbData,
    ino: u32,
) -> Result<Arc<Inode>, FsError> {
    let ext4_inode = sb_data.read_inode(ino)?;

    // Get file size
    let size = ((ext4_inode.i_size_high as u64) << 32) | (ext4_inode.i_size_lo as u64);

    // Get uid/gid (handle both 16-bit and 32-bit)
    let uid = ext4_inode.i_uid as u32;
    let gid = ext4_inode.i_gid as u32;

    // Create timespec
    let mtime = Timespec {
        sec: ext4_inode.i_mtime as i64,
        nsec: 0,
    };

    // Create VFS inode
    let vfs_inode = Arc::new(Inode::new(
        ino as u64,
        ext4_mode_to_vfs(ext4_inode.i_mode),
        uid,
        gid,
        size,
        mtime,
        Arc::downgrade(sb),
        &EXT4_INODE_OPS,
    ));

    // Set link count
    vfs_inode.nlink.store(ext4_inode.i_links_count as u32, core::sync::atomic::Ordering::Relaxed);

    // Store ext4-specific data (copy i_block to avoid packed struct reference)
    let i_block: [u32; 15] = unsafe {
        let ptr = core::ptr::addr_of!(ext4_inode.i_block);
        core::ptr::read_unaligned(ptr)
    };
    let mut extent_data = [0u8; 60];
    unsafe {
        core::ptr::copy_nonoverlapping(
            i_block.as_ptr() as *const u8,
            extent_data.as_mut_ptr(),
            60,
        );
    }

    vfs_inode.set_private(Arc::new(Ext4InodeData {
        ino,
        extent_data,
    }));

    Ok(vfs_inode)
}

// ============================================================================
// Ext4 File Operations
// ============================================================================

pub struct Ext4FileOps;

impl FileOps for Ext4FileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;
        let file_size = inode.get_size();
        let pos = file.get_pos();

        if pos >= file_size {
            return Ok(0);
        }

        let available = (file_size - pos) as usize;
        let to_read = core::cmp::min(buf.len(), available);

        if to_read == 0 {
            return Ok(0);
        }

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ext4_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4InodeData>()
            .ok_or(FsError::IoError)?;

        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_private = sb.get_private().ok_or(FsError::IoError)?;
        let sb_data = sb_private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4SbData>()
            .ok_or(FsError::IoError)?;

        let ext4_inode = sb_data.read_inode(ext4_data.ino)?;

        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_pos = pos + bytes_read as u64;
            let logical_block = current_pos / sb_data.block_size as u64;
            let offset_in_block = (current_pos % sb_data.block_size as u64) as usize;
            let chunk_size = core::cmp::min(
                sb_data.block_size as usize - offset_in_block,
                to_read - bytes_read,
            );

            let phys_block = sb_data.extent_map_block(&ext4_inode, logical_block)?;
            let block_data = read_block(&sb_data.bdev, phys_block, sb_data.block_size)?;

            buf[bytes_read..bytes_read + chunk_size]
                .copy_from_slice(&block_data[offset_in_block..offset_in_block + chunk_size]);

            bytes_read += chunk_size;
        }

        file.advance_pos(bytes_read as u64);
        Ok(bytes_read)
    }

    fn readdir(
        &self,
        file: &File,
        callback: &mut dyn FnMut(VfsDirEntry) -> bool,
    ) -> Result<(), FsError> {
        let inode = file.get_inode().ok_or(FsError::InvalidFile)?;

        if !inode.mode().is_dir() {
            return Err(FsError::NotADirectory);
        }

        let private = inode.get_private().ok_or(FsError::IoError)?;
        let ext4_data = private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4InodeData>()
            .ok_or(FsError::IoError)?;

        let sb = inode.superblock().ok_or(FsError::IoError)?;
        let sb_private = sb.get_private().ok_or(FsError::IoError)?;
        let sb_data = sb_private
            .as_ref()
            .as_any()
            .downcast_ref::<Ext4SbData>()
            .ok_or(FsError::IoError)?;

        let ext4_inode = sb_data.read_inode(ext4_data.ino)?;
        let file_size = ((ext4_inode.i_size_high as u64) << 32) | (ext4_inode.i_size_lo as u64);
        let num_blocks = (file_size + sb_data.block_size as u64 - 1) / sb_data.block_size as u64;

        for block_idx in 0..num_blocks {
            let phys_block = sb_data.extent_map_block(&ext4_inode, block_idx)?;
            let block_data = read_block(&sb_data.bdev, phys_block, sb_data.block_size)?;

            let mut offset = 0;
            while offset < block_data.len() {
                let entry: Ext4DirEntry2 = unsafe {
                    core::ptr::read_unaligned(block_data.as_ptr().add(offset) as *const _)
                };

                if entry.inode == 0 || entry.rec_len == 0 {
                    break;
                }

                let name_bytes = &block_data[offset + size_of::<Ext4DirEntry2>()..offset + size_of::<Ext4DirEntry2>() + entry.name_len as usize];

                let should_continue = callback(VfsDirEntry {
                    ino: entry.inode as u64,
                    file_type: ext4_file_type_to_vfs(entry.file_type),
                    name: name_bytes.to_vec(),
                });

                if !should_continue {
                    return Ok(());
                }

                offset += entry.rec_len as usize;
            }
        }

        Ok(())
    }
}

pub static EXT4_FILE_OPS: Ext4FileOps = Ext4FileOps;

// ============================================================================
// Ext4 Superblock Operations
// ============================================================================

pub struct Ext4SuperOps;

impl SuperOps for Ext4SuperOps {
    fn alloc_inode(
        &self,
        _sb: &Arc<SuperBlock>,
        _mode: InodeMode,
        _i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, FsError> {
        // Read-only filesystem
        Err(FsError::NotSupported)
    }
}

pub static EXT4_SUPER_OPS: Ext4SuperOps = Ext4SuperOps;

// ============================================================================
// Ext4 Mount Function
// ============================================================================

/// Mount function for ext4 with block device
fn ext4_mount_dev(
    fs_type: &'static FileSystemType,
    bdev: Arc<BlockDevice>,
) -> Result<Arc<SuperBlock>, FsError> {
    // Read and validate superblock
    let (_ext4_sb, sb_data) = Ext4SbData::read_superblock(&bdev)?;

    // Load group descriptors
    sb_data.load_group_descs(&_ext4_sb)?;

    // Create VFS superblock
    let sb = SuperBlock::new(fs_type, &EXT4_SUPER_OPS, 0);
    sb.set_private(Arc::new(sb_data));

    // Get superblock data
    let sb_private = sb.get_private().ok_or(FsError::IoError)?;
    let sb_data_ref = sb_private
        .as_ref()
        .as_any()
        .downcast_ref::<Ext4SbData>()
        .ok_or(FsError::IoError)?;

    // Create root inode (inode 2)
    let root_inode = create_vfs_inode(&sb, sb_data_ref, EXT4_ROOT_INO)?;

    // Create root dentry
    let root_dentry = Arc::new(Dentry::new_root(root_inode, Arc::downgrade(&sb)));

    // Set root in superblock
    sb.set_root(root_dentry);

    Ok(sb)
}

/// Ext4 filesystem type
pub static EXT4_TYPE: FileSystemType = FileSystemType {
    name: "ext4",
    fs_flags: 0,
    mount: |_| Err(FsError::NotSupported), // Requires block device
    mount_dev: Some(ext4_mount_dev),
    file_ops: &EXT4_FILE_OPS,
};
