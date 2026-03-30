use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct RootfsLayout {
    pub root: PathBuf,
    pub work_dir: PathBuf,
    pub tmp_dir: PathBuf,
}

pub fn roadmap() -> &'static str {
    "M2 scaffold: build minimal rootfs, bind runtime libraries, and manage mount cleanup."
}
