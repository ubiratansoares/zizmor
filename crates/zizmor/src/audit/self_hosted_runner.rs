//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "auditor" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use super::{Audit, AuditLoadError, audit_meta};
use crate::config::Config;
use crate::finding::Finding;
use crate::finding::location::Locatable as _;
use crate::models::workflow::runners::{Runner, RunnerEvidence};
use crate::models::workflow::{JobCommon as _, NormalJob};
use crate::{
    AuditState,
    audit::AuditError,
    finding::{Confidence, Persona, Severity},
};

pub(crate) struct SelfHostedRunner;

audit_meta!(
    SelfHostedRunner,
    "self-hosted-runner",
    "runs on a self-hosted runner"
);

#[async_trait::async_trait]
impl Audit for SelfHostedRunner {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let included_runners = &config.self_hosted_runner_config.deny_runners;
        let excluded_groups = &config.self_hosted_runner_config.allow_groups;

        let mut findings = Vec::new();
        let runners = job
            .runners(included_runners, excluded_groups)
            .collect::<Vec<_>>();

        let no_runners_defined = runners.is_empty();

        for runner in job.runners(included_runners, excluded_groups) {
            match runner {
                Runner::SelfHosted {
                    location,
                    evidence,
                    from_matrix,
                } => match evidence {
                    RunnerEvidence::ClassicSentinel | RunnerEvidence::ExplicitlyFlagged => {
                        let finding_builder = Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .persona(Persona::Auditor)
                            .add_location(
                                job.location()
                                    .primary()
                                    .with_keys(["runs-on".into()])
                                    .annotated("self-hosted runner used here"),
                            );

                        if from_matrix {
                            findings.push(
                                finding_builder
                                    .add_location(
                                        location
                                            .with_keys(["strategy".into()])
                                            .annotated("matrix declares self-hosted runner"),
                                    )
                                    .build(job.parent())?,
                            );
                        } else {
                            findings.push(finding_builder.build(job.parent())?);
                        };
                    }
                    RunnerEvidence::RunnerGroup => findings.push(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .persona(Persona::Auditor)
                            .add_location(
                                job.location()
                                    .primary()
                                    .with_keys(["runs-on".into()])
                                    .annotated("runner group used here"),
                            )
                            .build(job.parent())?,
                    ),
                },
                Runner::Indeterminate {
                    location,
                    from_matrix,
                    self_hosted_evidence,
                } => {
                    let mut finding_builder = Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Medium)
                        .persona(Persona::Auditor);

                    if from_matrix {
                        if self_hosted_evidence {
                            findings.push(
                                finding_builder
                                    .add_location(
                                        job.location()
                                            .primary()
                                            .with_keys(["runs-on".into()])
                                            .annotated("this matrix"),
                                    )
                                    .add_location(
                                        location
                                            .with_keys(["strategy".into()])
                                            .annotated("matrix may use self-hosted runners"),
                                    )
                                    .build(job.parent())?,
                            );
                        } else {
                            if let Some(matrix) = job.matrix() {
                                // Evaluate also indirect matrix expansions

                                let expansions = matrix.expansions();

                                let indirect_inclusions =
                                    expansions.indirect_inclusions().as_ref().map(|location| {
                                        location.clone().annotated(
                                            "indirect `include` adds unanalyzable combinations",
                                        )
                                    });

                                if let Some(indirect_inclusions) = indirect_inclusions {
                                    finding_builder =
                                        finding_builder.add_location(indirect_inclusions);
                                    findings.push(finding_builder.build(job.parent())?);
                                }
                            }
                        };
                    } else {
                        findings.push(
                            finding_builder
                                .add_location(
                                    job.location()
                                        .primary()
                                        .with_keys(["runs-on".into()])
                                        .annotated(
                                            "expression may expand into a self-hosted runner",
                                        ),
                                )
                                .build(job.parent())?,
                        );
                    }
                }
                _ => {}
            }
        }

        // Do not miss a fully indirect matrix
        if let Some(matrix) = job.matrix()
            && no_runners_defined
        {
            let indirect_matrix =
                matrix
                    .expansions()
                    .indirectly_expanded()
                    .as_ref()
                    .map(|location| {
                        location
                            .clone()
                            .annotated("indirect `matrix` adds unanalyzable combinations")
                    });

            if let Some(indirect_matrix_location) = indirect_matrix {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Medium)
                        .persona(Persona::Auditor)
                        .add_location(
                            job.location()
                                .primary()
                                .with_keys(["runs-on".into()])
                                .annotated("this matrix"),
                        )
                        .add_location(indirect_matrix_location)
                        .build(job.parent())?,
                );
            }
        }

        Ok(findings)
    }
}
