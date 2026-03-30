use sandbox_core::ResourceLimits;

#[derive(Debug, Clone)]
pub struct CgroupPlan {
    pub scope_name: String,
    pub limits: ResourceLimits,
}

impl CgroupPlan {
    pub fn new(scope_name: impl Into<String>, limits: ResourceLimits) -> Self {
        Self {
            scope_name: scope_name.into(),
            limits,
        }
    }
}

pub fn roadmap() -> &'static str {
    "M3 scaffold: manage cgroup v2 paths, write limits, and collect resource usage."
}
