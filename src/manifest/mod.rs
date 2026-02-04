pub mod apply;
pub mod builder;
pub mod diff;
pub mod io;
pub mod model;

pub use apply::ManifestApplier;
pub use builder::{FileDescriptor, ManifestBuilder, ManifestDraft};
pub use diff::{DiffOutcome, ManifestDiffer};
pub use io::{load_manifest, save_manifest, ManifestIoError};
pub use model::{
    EncryptionMetadata, EntryState, EntryType, Manifest, ManifestArchive, ManifestEntry,
    ManifestEntryMetadata, ManifestFile, ManifestRoot, ManifestSummary, SignatureMetadata,
};
