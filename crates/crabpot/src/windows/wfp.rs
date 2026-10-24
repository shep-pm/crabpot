//! What `srt-win wfp verify` says about the egress fence, as upstream's
//! `interpretWindowsWfpVerify` reads it (`src/sandbox/windows-sandbox-utils.ts`).

use serde::Deserialize;

use super::srt::Output;
use super::status::refusal_for_exit;
use crate::StartError;

/// `wfp verify`'s one line of JSON, as far as a verdict reads it. A probe the
/// line leaves out was not made.
#[derive(Deserialize)]
struct Report {
    egress_probe: Option<String>,
    low_integrity_probe: Option<String>,
    low_integrity_loopback_probe: Option<String>,
    untrusted_integrity_probe: Option<String>,
    untrusted_integrity_loopback_probe: Option<String>,
    allow_loopback: Option<bool>,
    allow_loopback_mismatch: Option<bool>,
}

/// Judges one run of `wfp verify`: the fence is active, or the error says why
/// it is not known to be.
///
/// A residual the run names is not judged: no filter closes it, and it does not
/// change the exit code.
pub(super) fn interpret(output: &Output) -> Result<(), StartError> {
    if let Some(error) = output.code.and_then(refusal_for_exit) {
        return Err(error);
    }
    let exit = output.code.map_or_else(
        || "without an exit code".to_owned(),
        |c| format!("with {c}"),
    );
    let report: Report =
        serde_json::from_str(&output.stdout).map_err(|_| StartError::FenceUnverified {
            detail: format!(
                "`srt-win wfp verify` exited {exit} and printed what cannot be read ({})",
                output.stderr.trim()
            ),
        })?;
    if output.code == Some(19) || report.allow_loopback_mismatch == Some(true) {
        return Err(StartError::LoopbackMismatch);
    }
    // The attempts the fence must refuse: one that got through rejects whatever
    // the exit code says.
    let probes = [
        ("egress_probe", &report.egress_probe),
        ("low_integrity_probe", &report.low_integrity_probe),
        (
            "low_integrity_loopback_probe",
            &report.low_integrity_loopback_probe,
        ),
        (
            "untrusted_integrity_probe",
            &report.untrusted_integrity_probe,
        ),
        (
            "untrusted_integrity_loopback_probe",
            &report.untrusted_integrity_loopback_probe,
        ),
    ];
    let mut through: Vec<&str> = probes
        .iter()
        .filter(|(_, outcome)| matches!(outcome.as_deref(), Some("connected" | "refused")))
        .map(|(name, _)| *name)
        .collect();
    // With loopback open nothing listens at the plain attempt's port, so no
    // answer in time is no refusal by the filter either.
    if report.allow_loopback == Some(true) && report.egress_probe.as_deref() == Some("unreachable")
    {
        through.push("egress_probe");
    }
    if output.code == Some(3) || !through.is_empty() {
        return Err(StartError::FenceInactive {
            detail: if through.is_empty() {
                "a direct outbound connect was not blocked".to_owned()
            } else {
                format!("not blocked: {}", through.join(", "))
            },
        });
    }
    if output.code != Some(0) {
        return Err(StartError::FenceUnverified {
            detail: format!(
                "probe was '{}' and `srt-win wfp verify` exited {exit} ({})",
                report.egress_probe.as_deref().unwrap_or("missing"),
                output.stderr.trim()
            ),
        });
    }
    // Exit 0 alone is not a pass: the plain attempt must say `blocked`.
    if report.egress_probe.as_deref() != Some("blocked") {
        return Err(StartError::FenceUnverified {
            detail: format!(
                "`srt-win wfp verify` exited 0 and reported the plain attempt as '{}'",
                report.egress_probe.as_deref().unwrap_or("missing")
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::srt::fake::exit;

    fn verify(code: i32, json: &str) -> Result<(), StartError> {
        interpret(&exit(code, json))
    }

    #[test]
    fn a_blocked_plain_attempt_passes() {
        assert_eq!(verify(0, r#"{"egress_probe":"blocked"}"#), Ok(()));
    }

    #[test]
    fn a_residual_does_not_fail_a_pass() {
        let json = r#"{"egress_probe":"blocked","anonymous_probe":"connected",
            "residuals":["anonymous-egress"]}"#;

        assert_eq!(verify(0, json), Ok(()));
    }

    #[test]
    fn exit_19_is_a_loopback_mismatch() {
        let json = r#"{"egress_probe":"not-run","allow_loopback_mismatch":true}"#;

        assert_eq!(verify(19, json), Err(StartError::LoopbackMismatch));
    }

    #[test]
    fn a_probe_that_got_through_is_an_inactive_fence_whatever_the_exit_says() {
        let json = r#"{"egress_probe":"blocked","low_integrity_probe":"refused"}"#;

        assert_eq!(
            verify(0, json),
            Err(StartError::FenceInactive {
                detail: "not blocked: low_integrity_probe".to_owned()
            })
        );
    }

    #[test]
    fn exit_3_is_an_inactive_fence() {
        let error = verify(3, r#"{"egress_probe":"connected"}"#).unwrap_err();

        assert!(matches!(error, StartError::FenceInactive { .. }), "{error}");
    }

    #[test]
    fn an_unanswered_plain_attempt_with_loopback_open_is_an_inactive_fence() {
        let json = r#"{"egress_probe":"unreachable","allow_loopback":true}"#;

        assert!(matches!(
            verify(2, json),
            Err(StartError::FenceInactive { .. })
        ));
    }

    #[test]
    fn a_failed_run_with_no_attempt_through_is_not_verified() {
        let error = verify(2, r#"{"egress_probe":"unreachable"}"#).unwrap_err();

        assert!(
            matches!(error, StartError::FenceUnverified { .. }),
            "{error}"
        );
    }

    #[test]
    fn exit_0_with_a_plain_attempt_that_was_not_blocked_is_not_verified() {
        let error = verify(0, r#"{"egress_probe":"error"}"#).unwrap_err();

        assert!(
            matches!(error, StartError::FenceUnverified { .. }),
            "{error}"
        );
    }

    #[test]
    fn output_that_is_not_json_is_not_verified() {
        let error = verify(0, "nope").unwrap_err();

        assert!(
            matches!(error, StartError::FenceUnverified { .. }),
            "{error}"
        );
    }

    #[test]
    fn exit_15_and_18_are_their_own_errors() {
        assert_eq!(verify(15, ""), Err(StartError::NotProvisioned));
        assert_eq!(verify(18, ""), Err(StartError::SeclogonDisabled));
    }
}
