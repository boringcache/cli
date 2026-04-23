use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct CiContext {
    providers: Vec<&'static str>,
    os_tag: Option<String>,
    arch_tag: Option<String>,
    benchmark: bool,
    run_context: Option<CiRunContext>,
}

impl CiContext {
    pub(super) fn new(
        providers: Vec<&'static str>,
        os_tag: Option<String>,
        arch_tag: Option<String>,
        benchmark: bool,
        run_context: Option<CiRunContext>,
    ) -> Self {
        Self {
            providers,
            os_tag,
            arch_tag,
            benchmark,
            run_context,
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

    pub fn run_context(&self) -> Option<&CiRunContext> {
        self.run_context.as_ref()
    }

    pub fn inferred_project_hint(&self) -> Option<String> {
        self.run_context
            .as_ref()
            .and_then(|context| context.inferred_project_hint(self.benchmark))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiRunContext {
    pub provider: String,
    pub run_uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_attempt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    pub source_ref_type: CiSourceRefType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_ref_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_ref_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_started_at: Option<String>,
}

impl CiRunContext {
    pub fn inferred_project_hint(&self, benchmark_mode: bool) -> Option<String> {
        let repository = self.repository.as_deref()?;
        let repo_name = repository.rsplit('/').next()?.trim();
        if repo_name.is_empty() {
            return None;
        }

        let hint = if benchmark_mode {
            repo_name.strip_prefix("benchmark-").unwrap_or(repo_name)
        } else {
            repo_name
        };

        Some(hint.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CiSourceRefType {
    Branch,
    Tag,
    PullRequest,
    Other,
}
