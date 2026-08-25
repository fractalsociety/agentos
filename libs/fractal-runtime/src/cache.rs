//! Content-addressed AOT artifact cache.

use crate::encode::{COMPILER_ID, WASM_INTERFACE_VERSION};
use crate::validate::CompileError;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CacheError {
    #[error("{0}")]
    Message(String),
}

impl From<CacheError> for CompileError {
    fn from(value: CacheError) -> Self {
        CompileError::Cache(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub digest: [u8; 32],
}

impl CacheKey {
    pub fn from_ir(ir_bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(COMPILER_ID);
        h.update(WASM_INTERFACE_VERSION.to_le_bytes());
        h.update(ir_bytes);
        Self {
            digest: h.finalize().into(),
        }
    }

    pub fn hex(&self) -> String {
        self.digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Debug)]
pub struct ArtifactCache {
    root: PathBuf,
}

impl ArtifactCache {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|e| CacheError::Message(e.to_string()))?;
        Ok(Self { root })
    }

    fn path_for(&self, key: &CacheKey) -> PathBuf {
        self.root.join(format!("{}.wasm", key.hex()))
    }

    pub fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        fs::read(self.path_for(key)).ok()
    }

    pub fn put(&mut self, key: &CacheKey, wasm: &[u8]) -> Result<(), CacheError> {
        let path = self.path_for(key);
        let tmp = path.with_extension("wasm.tmp");
        fs::write(&tmp, wasm).map_err(|e| CacheError::Message(e.to_string()))?;
        fs::rename(&tmp, &path).map_err(|e| CacheError::Message(e.to_string()))?;
        Ok(())
    }
}
