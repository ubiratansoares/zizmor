use std::sync::LazyLock;

use github_actions_models::common::Uses;
use subfeature::Subfeature;

use crate::models::workflow::NormalJob;
use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::{StepCommon, action::CompositeStep, uses::RepositoryUsesPattern},
    state::AuditState,
};

pub(crate) struct SuperfluousActions;

audit_meta!(
    SuperfluousActions,
    "superfluous-actions",
    "action functionality is already included by the runner"
);

#[async_trait::async_trait]
impl Audit for SuperfluousActions {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut results = vec![];
        for step in job.steps() {
            results.extend(
                self.process_step(&step, job.runs_on_self_hosted_runner())
                    .await?,
            );
        }
        Ok(results)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, false).await
    }
}

/// Flags in which scenarios we explicitly want to drop this check
/// to reduce false-positives
#[derive(Debug, PartialEq)]
enum SkipCriteria {
    Never,
    SelfHostedRunnerDetected,
}

#[allow(clippy::unwrap_used, clippy::type_complexity)]
static SUPERFLUOUS_ACTIONS: LazyLock<
    Vec<(
        RepositoryUsesPattern,
        &str,
        Persona,
        Confidence,
        SkipCriteria,
    )>,
> = LazyLock::new(|| {
    vec![
        (
            "ncipollo/release-action".parse().unwrap(),
            "use `gh release` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "softprops/action-gh-release".parse().unwrap(),
            "use `gh release` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "elgohr/Github-Release-Action".parse().unwrap(),
            "use `gh release` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "peter-evans/create-pull-request".parse().unwrap(),
            "use `gh pr create` in a script step",
            // NOTE(ww): Currently pedantic because creating a PR
            // with just `gh` and `git` is pretty cumbersome.
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
        (
            "peter-evans/create-or-update-comment".parse().unwrap(),
            "use `gh pr comment` or `gh issue comment` in a script step",
            // NOTE(ww): Currently pedantic because `gh` doesn't support
            // editing a comment by ID.
            // See: <https://github.com/cli/cli/issues/3613>
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
        (
            "dacbd/create-issue-action".parse().unwrap(),
            "use `gh issue create` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "actions-ecosystem/action-add-labels".parse().unwrap(),
            "use `gh issue edit --add-label` or `gh pr edit --add-label` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "actions-ecosystem/action-remove-labels".parse().unwrap(),
            "use `gh issue edit --remove-label` or `gh pr edit --remove-label` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "svenstaro/upload-release-action".parse().unwrap(),
            "use `gh release create` and `gh release upload` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "addnab/docker-run-action".parse().unwrap(),
            "use `docker run` in a script step, or use a container step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "sergeysova/jq-action".parse().unwrap(),
            "use `jq` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "dtolnay/rust-toolchain".parse().unwrap(),
            "use `rustup` and/or `cargo` in a script step",
            // NOTE(ww): Currently skipped on self-hosted runners because this
            // action does some additional environment setup, and users find the
            // finding here disruptive.
            // See: <https://github.com/zizmorcore/zizmor/issues/1817>
            // See: <https://github.com/zizmorcore/zizmor/issues/1865>
            Persona::Pedantic,
            Confidence::Medium,
            SkipCriteria::SelfHostedRunnerDetected,
        ),
        (
            "stefanzweifel/git-auto-commit-action".parse().unwrap(),
            "use `git add`, `git commit`, and `git push` in a script step",
            // NOTE: Currently pedantic because replicating this action's
            // full behaviour (empty commit detection, auth setup, etc.)
            // requires multiple git commands and some care.
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
        (
            "EndBug/add-and-commit".parse().unwrap(),
            "use `git add`, `git commit`, and `git push` in a script step",
            // NOTE: Currently pedantic because replicating this action's
            // full behaviour (empty commit detection, auth setup, etc.)
            // requires multiple git commands and some care.
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
    ]
});

impl SuperfluousActions {
    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        self_hosted_runner: bool,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let no_findings = Ok(vec![]);

        let Some(Uses::Repository(uses)) = step.uses() else {
            return no_findings;
        };

        let mut findings = vec![];
        for (pattern, recommendation, persona, confidence, skip_criteria) in
            SUPERFLUOUS_ACTIONS.iter()
        {
            // So far we check whether to drop this check on self-hosted runners
            // In the future we may evaluate other criteria as well
            if self_hosted_runner && *skip_criteria == SkipCriteria::SelfHostedRunnerDetected {
                continue;
            }

            if pattern.matches(&uses.into()) {
                findings.push(
                    Self::finding()
                        .confidence(*confidence)
                        .severity(Severity::Informational)
                        .persona(*persona)
                        .add_location(step.location_with_grip())
                        .add_location(
                            step.location()
                                .with_keys(["uses".into()])
                                .subfeature(Subfeature::new(0, uses.raw()))
                                .annotated(*recommendation)
                                .primary(),
                        )
                        .add_location(step.location().hidden())
                        .build(step)?,
                );
            }
        }

        Ok(findings)
    }
}
