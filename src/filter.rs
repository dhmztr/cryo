use crate::errors::CryoErrors;
use globset::{Glob, GlobSet, GlobSetBuilder};

pub(crate) fn build_matcher(patterns: &[String]) -> Result<GlobSet, CryoErrors> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p).map_err(|_| CryoErrors::InvalidPattern)?);
    }
    builder.build().map_err(|_| CryoErrors::InvalidPattern)
}
