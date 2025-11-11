pub mod apply;
pub mod builder;
pub mod cache;
pub mod diff;
pub mod io;
pub mod model;

pub use apply::ManifestApplier;
pub use builder::{FileDescriptor, ManifestBuilder, ManifestDraft};
pub use cache::ManifestCache;
pub use diff::{DiffOutcome, ManifestDiffer};
pub use io::{load_manifest, save_manifest, ManifestIoError};
pub use model::{
    ChunkInfo, ChunkMeta, ChunkSpan, EntryState, EntryType, Manifest, ManifestArchive,
    ManifestEntry, ManifestEntryMetadata, ManifestFile, ManifestRoot, ManifestSummary,
};
