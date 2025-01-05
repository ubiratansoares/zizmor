use crate::audit::{audit_meta, Audit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::coordinate::{Control, ControlFieldType, Toggle, Usage, UsesCoordinate};
use crate::models::{Job, Step, Steps, Uses};
use crate::state::AuditState;
use github_actions_models::common::expr::ExplicitExpr;
use github_actions_models::common::Env;
use github_actions_models::workflow::event::{BareEvent, BranchFilters, OptionalBody};
use github_actions_models::workflow::job::StepBody;
use github_actions_models::workflow::Trigger;
use std::ops::Deref;
use std::sync::LazyLock;

/// The list of know cache-aware actions
/// In the future we can easily retrieve this list from the static API,
/// since it should be easily serializable
static KNOWN_CACHE_AWARE_ACTIONS: LazyLock<Vec<UsesCoordinate>> = LazyLock::new(|| {
    vec![
        // https://github.com/actions/cache/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("actions/cache").unwrap(),
            control: Control::new(Toggle::OptOut, "lookup-only", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/actions/setup-java/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("actions/setup-java").unwrap(),
            control: Control::new(Toggle::OptIn, "cache", ControlFieldType::String),
            enabled_by_default: false,
        },
        // https://github.com/actions/setup-go/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("actions/setup-go").unwrap(),
            control: Control::new(Toggle::OptIn, "cache", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/actions/setup-node/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("actions/setup-node").unwrap(),
            control: Control::new(Toggle::OptIn, "cache", ControlFieldType::String),
            enabled_by_default: false,
        },
        // https://github.com/actions/setup-python/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("actions/setup-python").unwrap(),
            control: Control::new(Toggle::OptIn, "cache", ControlFieldType::String),
            enabled_by_default: false,
        },
        // https://github.com/actions/setup-dotnet/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("actions/setup-dotnet").unwrap(),
            control: Control::new(Toggle::OptIn, "cache", ControlFieldType::Boolean),
            enabled_by_default: false,
        },
        // https://github.com/astral-sh/setup-uv/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("astral-sh/setup-uv").unwrap(),
            control: Control::new(Toggle::OptOut, "enable-cache", ControlFieldType::String),
            enabled_by_default: true,
        },
        // https://github.com/Swatinem/rust-cache/blob/master/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("Swatinem/rust-cache").unwrap(),
            control: Control::new(Toggle::OptOut, "lookup-only", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/ruby/setup-ruby/blob/master/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("ruby/setup-ruby").unwrap(),
            control: Control::new(Toggle::OptIn, "bundler-cache", ControlFieldType::Boolean),
            enabled_by_default: false,
        },
        // https://github.com/PyO3/maturin-action/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("PyO3/maturin-action").unwrap(),
            control: Control::new(Toggle::OptIn, "sccache", ControlFieldType::Boolean),
            enabled_by_default: false,
        },
        // https://github.com/mlugg/setup-zig/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("mlugg/setup-zig").unwrap(),
            control: Control::new(Toggle::OptIn, "use-cache", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/oven-sh/setup-bun/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("oven-sh/setup-bun").unwrap(),
            control: Control::new(Toggle::OptOut, "no-cache", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/DeterminateSystems/magic-nix-cache-action/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("DeterminateSystems/magic-nix-cache-action").unwrap(),
            control: Control::new(Toggle::OptIn, "use-gha-cache", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/graalvm/setup-graalvm/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("graalvm/setup-graalvm").unwrap(),
            control: Control::new(Toggle::OptIn, "cache", ControlFieldType::String),
            enabled_by_default: false,
        },
        // https://github.com/gradle/actions/blob/main/setup-gradle/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("gradle/actions/setup-gradle").unwrap(),
            control: Control::new(Toggle::OptOut, "cache-disabled", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/docker/setup-buildx-action/blob/master/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("docker/setup-buildx-action").unwrap(),
            control: Control::new(Toggle::OptIn, "cache-binary", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/actions-rust-lang/setup-rust-toolchain/blob/main/action.yml
        UsesCoordinate::Configurable {
            uses: Uses::from_step("actions-rust-lang/setup-rust-toolchain").unwrap(),
            control: Control::new(Toggle::OptIn, "cache", ControlFieldType::Boolean),
            enabled_by_default: true,
        },
        // https://github.com/Mozilla-Actions/sccache-action/blob/main/action.yml
        UsesCoordinate::NotConfigurable(Uses::from_step("Mozilla-Actions/sccache-action").unwrap()),
        // https://github.com/nix-community/cache-nix-action/blob/main/action.yml
        UsesCoordinate::NotConfigurable(Uses::from_step("nix-community/cache-nix-action").unwrap()),
    ]
});

/// A list of well-know publisher actions
/// In the future we can retrieve this list from the static API
static KNOWN_PUBLISHER_ACTIONS: LazyLock<Vec<Uses>> = LazyLock::new(|| {
    vec![
        // Public packages and/or binary distribution channels
        Uses::from_step("pypa/gh-action-pypi-publish").unwrap(),
        Uses::from_step("rubygems/release-gem").unwrap(),
        Uses::from_step("jreleaser/release-action").unwrap(),
        Uses::from_step("goreleaser/goreleaser-action").unwrap(),
        // Github releases
        Uses::from_step("softprops/action-gh-release").unwrap(),
        Uses::from_step("release-drafter/release-drafter").unwrap(),
        Uses::from_step("googleapis/release-please-action").unwrap(),
        // Container registries
        Uses::from_step("docker/build-push-action").unwrap(),
        Uses::from_step("redhat-actions/push-to-registry").unwrap(),
        // Cloud + Edge providers
        Uses::from_step("aws-actions/amazon-ecs-deploy-task-definition ").unwrap(),
        Uses::from_step("aws-actions/aws-cloudformation-github-deploy").unwrap(),
        Uses::from_step("Azure/aci-deploy").unwrap(),
        Uses::from_step("Azure/container-apps-deploy-action").unwrap(),
        Uses::from_step("Azure/functions-action").unwrap(),
        Uses::from_step("Azure/sql-action").unwrap(),
        Uses::from_step("cloudflare/wrangler-action").unwrap(),
        Uses::from_step("google-github-actions/deploy-appengine").unwrap(),
        Uses::from_step("google-github-actions/deploy-cloudrun").unwrap(),
        Uses::from_step("google-github-actions/deploy-cloud-functions").unwrap(),
    ]
});

enum PublishingArtifactsScenario<'w> {
    UsingTypicalWorkflowTrigger,
    UsingWellKnowPublisherAction(Step<'w>),
}

pub(crate) struct CachePoisoning;

audit_meta!(
    CachePoisoning,
    "cache-poisoning",
    "runtime artifacts potentially vulnerable to a cache poisoning attack"
);

impl CachePoisoning {
    fn trigger_used_when_publishing_artifacts(&self, trigger: &Trigger) -> bool {
        match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::Release,
            Trigger::BareEvents(events) => events.contains(&BareEvent::Release),
            Trigger::Events(events) => match &events.push {
                OptionalBody::Body(body) => {
                    let pushing_new_tag = &body.tag_filters.is_some();
                    let pushing_to_release_branch =
                        if let Some(BranchFilters::Branches(branches)) = &body.branch_filters {
                            branches
                                .iter()
                                .any(|branch| branch.to_lowercase().contains("release"))
                        } else {
                            false
                        };

                    *pushing_new_tag || pushing_to_release_branch
                }
                _ => false,
            },
        }
    }

    fn detected_well_known_publisher_step(steps: Steps) -> Option<Step> {
        steps.into_iter().find(|step| {
            let Some(Uses::Repository(target_uses)) = step.uses() else {
                return false;
            };

            KNOWN_PUBLISHER_ACTIONS.iter().any(|publisher| {
                let Uses::Repository(well_known_uses) = publisher else {
                    return false;
                };

                target_uses.matches(*well_known_uses)
            })
        })
    }

    fn is_job_publishing_artifacts<'w>(
        &self,
        trigger: &Trigger,
        steps: Steps<'w>,
    ) -> Option<PublishingArtifactsScenario<'w>> {
        if self.trigger_used_when_publishing_artifacts(trigger) {
            return Some(PublishingArtifactsScenario::UsingTypicalWorkflowTrigger);
        };

        let well_know_publisher = CachePoisoning::detected_well_known_publisher_step(steps)?;

        Some(PublishingArtifactsScenario::UsingWellKnowPublisherAction(
            well_know_publisher,
        ))
    }

    fn evaluate_user_defined_opt_in(
        cache_control_input: &str,
        env: &Env,
        field_type: &ControlFieldType,
    ) -> Option<Usage> {
        match env.get(cache_control_input) {
            None => None,
            Some(value) => match value.to_string().as_str() {
                "true" if matches!(field_type, ControlFieldType::Boolean) => {
                    Some(Usage::DirectOptIn)
                }
                "false" if matches!(field_type, ControlFieldType::Boolean) => {
                    // Explicitly opts out from caching
                    None
                }
                other => match ExplicitExpr::from_curly(other) {
                    None if matches!(field_type, ControlFieldType::String) => {
                        Some(Usage::DirectOptIn)
                    }
                    None => None,
                    Some(_) => Some(Usage::ConditionalOptIn),
                },
            },
        }
    }

    fn usage_of_controllable_caching(
        &self,
        env: &Env,
        control: &Control,
        enabled_by_default: bool,
    ) -> Option<Usage> {
        let cache_control_input = env.keys().find(|k| control.field_name == *k);

        match cache_control_input {
            // when not using the specific Action input to control caching behaviour,
            // we evaluate whether it uses caching by default
            None => {
                if enabled_by_default {
                    Some(Usage::DefaultActionBehaviour)
                } else {
                    None
                }
            }

            // otherwise, we infer from the value assigned to the cache control input
            Some(key) => {
                // first, we extract the value assigned to that input
                let declared_usage =
                    CachePoisoning::evaluate_user_defined_opt_in(key, env, &control.field_type);

                // we now evaluate the extracted value against the opt-in semantics
                match &declared_usage {
                    Some(Usage::DirectOptIn) => {
                        match control.toggle {
                            // in this case, we just follow the opt-in
                            Toggle::OptIn => declared_usage,
                            // otherwise, the user opted for disabling the cache
                            // hence we don't return a Usage
                            Toggle::OptOut => None,
                        }
                    }
                    // Because we can't evaluate expressions, there is nothing to do
                    // regarding Usage::ConditionalOptIn
                    _ => declared_usage,
                }
            }
        }
    }

    fn evaluate_cache_usage(&self, target_step: &str, env: &Env) -> Option<Usage> {
        let known_action = KNOWN_CACHE_AWARE_ACTIONS.iter().find(|action| {
            let Uses::Repository(well_known_uses) = action.uses() else {
                return false;
            };

            let Some(Uses::Repository(target_uses)) = Uses::from_step(target_step) else {
                return false;
            };

            target_uses.matches(well_known_uses)
        })?;

        match &known_action {
            UsesCoordinate::Configurable {
                uses: _,
                control,
                enabled_by_default,
            } => self.usage_of_controllable_caching(env, control, *enabled_by_default),
            UsesCoordinate::NotConfigurable(_) => Some(Usage::Always),
        }
    }

    fn uses_cache_aware_step<'w>(
        &self,
        step: &Step<'w>,
        scenario: &PublishingArtifactsScenario<'w>,
    ) -> Option<Finding<'w>> {
        let StepBody::Uses { ref uses, ref with } = &step.deref().body else {
            return None;
        };

        let cache_usage = self.evaluate_cache_usage(uses, with)?;

        let (yaml_key, annotation) = match cache_usage {
            Usage::Always => ("uses", "caching always restored here"),
            Usage::DefaultActionBehaviour => ("uses", "cache enabled by default here"),
            Usage::DirectOptIn => ("with", "opt-in for caching here"),
            Usage::ConditionalOptIn => ("with", "opt-in for caching might happen here"),
        };

        let finding = match scenario {
            PublishingArtifactsScenario::UsingTypicalWorkflowTrigger => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    step.workflow()
                        .location()
                        .with_keys(&["on".into()])
                        .annotated("generally used when publishing artifacts generated at runtime"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&[yaml_key.into()])
                        .annotated(annotation),
                )
                .build(step.workflow()),
            PublishingArtifactsScenario::UsingWellKnowPublisherAction(publisher) => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    publisher
                        .location()
                        .with_keys(&["uses".into()])
                        .annotated("runtime artifacts usually published here"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&[yaml_key.into()])
                        .annotated(annotation),
                )
                .build(step.workflow()),
        };

        finding.ok()
    }
}

impl Audit for CachePoisoning {
    fn new(_: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'w>(&self, job: &Job<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];
        let steps = job.steps();
        let trigger = &job.parent().on;

        let Some(scenario) = self.is_job_publishing_artifacts(trigger, steps) else {
            return Ok(findings);
        };

        for step in job.steps() {
            if let Some(finding) = self.uses_cache_aware_step(&step, &scenario) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}
