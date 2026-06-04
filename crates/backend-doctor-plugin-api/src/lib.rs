pub use backend_doctor_core::{
    AnalysisConfig, AnalysisFacts, AnalysisFacts as PluginAnalysisFacts, ExternalCommandExecution,
    ExternalCommandInvocation, ExternalCommandRunner, ExternalCommandSpec, ExternalCommandStatus,
    ExternalToolConfig, ExternalToolVersion,
};
use backend_doctor_core::{Finding, RuleMetadata};
use backend_doctor_detect::ProjectGraph;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginActivation {
    Enabled,
    Disabled { reason: String },
}

pub trait DoctorPlugin {
    fn id(&self) -> &'static str;
    fn rules(&self) -> Vec<RuleMetadata>;
    fn detect(&self, project: &ProjectGraph) -> PluginActivation;
    fn run(&self, project: &ProjectGraph) -> Vec<Finding>;
}

pub const DOCTOR_PLUGIN_API_VERSION: u16 = 1;
pub const DOCTOR_PLUGIN_ANALYSIS_API_VERSION: u16 = 2;

pub trait DoctorPluginV2: DoctorPlugin {
    fn api_version(&self) -> u16 {
        DOCTOR_PLUGIN_ANALYSIS_API_VERSION
    }

    fn analyze(&self, _project: &ProjectGraph) -> AnalysisFacts {
        AnalysisFacts::empty()
    }

    fn run_with_analysis(&self, project: &ProjectGraph, _facts: &AnalysisFacts) -> Vec<Finding> {
        self.run(project)
    }
}

pub trait AnalysisPlugin: DoctorPluginV2 {}

impl<T> AnalysisPlugin for T where T: DoctorPluginV2 {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn disabled_activation_carries_reason() {
        let activation = PluginActivation::Disabled {
            reason: "not detected".to_string(),
        };
        assert_eq!(
            activation,
            PluginActivation::Disabled {
                reason: "not detected".to_string()
            }
        );
    }

    struct NoopPlugin;

    impl DoctorPlugin for NoopPlugin {
        fn id(&self) -> &'static str {
            "noop"
        }

        fn rules(&self) -> Vec<RuleMetadata> {
            Vec::new()
        }

        fn detect(&self, _project: &ProjectGraph) -> PluginActivation {
            PluginActivation::Enabled
        }

        fn run(&self, _project: &ProjectGraph) -> Vec<Finding> {
            Vec::new()
        }
    }

    impl DoctorPluginV2 for NoopPlugin {}

    #[test]
    fn v2_plugin_defaults_preserve_v1_behavior() {
        let plugin = NoopPlugin;
        let project = ProjectGraph::empty(PathBuf::from("."));
        let facts = plugin.analyze(&project);

        assert_eq!(plugin.api_version(), DOCTOR_PLUGIN_ANALYSIS_API_VERSION);
        assert!(facts.is_empty());
        assert_eq!(
            plugin.run_with_analysis(&project, &facts),
            plugin.run(&project)
        );
    }
}
