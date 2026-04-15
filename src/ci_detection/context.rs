#[derive(Debug, Clone, Default)]
pub struct CiContext {
    providers: Vec<&'static str>,
    os_tag: Option<String>,
    arch_tag: Option<String>,
    benchmark: bool,
}

impl CiContext {
    pub(super) fn new(
        providers: Vec<&'static str>,
        os_tag: Option<String>,
        arch_tag: Option<String>,
        benchmark: bool,
    ) -> Self {
        Self {
            providers,
            os_tag,
            arch_tag,
            benchmark,
        }
    }

    pub fn is_ci(&self) -> bool {
        !self.providers.is_empty()
    }

    pub fn label(&self) -> String {
        if self.is_ci() {
            self.providers.join(",")
        } else {
            "local".to_string()
        }
    }

    pub fn tags(&self) -> Vec<String> {
        let mut tags = Vec::new();
        tags.push(self.label());
        if let Some(os) = &self.os_tag {
            tags.push(os.clone());
        }
        if let Some(arch) = &self.arch_tag {
            tags.push(arch.clone());
        }
        if self.benchmark {
            tags.push("benchmark".to_string());
        }
        tags
    }
}
