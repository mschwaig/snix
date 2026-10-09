use crate::{
    B3Digest,
    proto::{GetBlobRequest, StatBlobRequest},
};

impl StatBlobRequest {
    pub fn with_digest(digest: B3Digest) -> Self {
        Self {
            digest: digest.into(),
        }
    }
}

impl GetBlobRequest {
    pub fn with_digest(digest: B3Digest) -> Self {
        Self {
            digest: digest.into(),
        }
    }
}
