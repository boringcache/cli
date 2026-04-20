use crate::serve::state::{AppState, StartupOciExecution};

pub(crate) async fn prefetch_selected_refs(
    state: &AppState,
    oci_prefetch_refs: Vec<(String, String)>,
    oci_hydration_policy: crate::serve::OciHydrationPolicy,
) {
    if oci_prefetch_refs.is_empty() {
        return;
    }

    eprintln!(
        "Prefetch: resolving {} selected OCI manifest refs",
        oci_prefetch_refs.len()
    );
    let oci_started_at = std::time::Instant::now();
    let mut completed_refs = 0usize;
    let mut total_unique_blobs = 0usize;
    let mut inserted = 0usize;
    let mut failures = 0usize;
    let mut cold_blobs = 0usize;
    let mut background_body_refs = Vec::new();
    let mut body_inserted = 0usize;
    let mut body_failures = 0usize;
    let mut body_cold_blobs = 0usize;
    let hydrate_before_ready = oci_hydration_policy.waits_before_ready();

    for (name, reference) in oci_prefetch_refs {
        match crate::serve::http::handlers::manifest::prefetch_manifest_reference(
            state,
            &name,
            &reference,
            hydrate_before_ready,
        )
        .await
        {
            Ok((stats, missing_local_blobs)) => {
                completed_refs = completed_refs.saturating_add(1);
                total_unique_blobs = total_unique_blobs.saturating_add(stats.total_unique_blobs);
                inserted = inserted.saturating_add(stats.inserted);
                failures = failures.saturating_add(stats.failures);
                cold_blobs = cold_blobs.saturating_add(missing_local_blobs);
                body_inserted = body_inserted.saturating_add(stats.inserted);
                body_failures = body_failures.saturating_add(stats.failures);
                body_cold_blobs = body_cold_blobs.saturating_add(missing_local_blobs);
                if matches!(
                    oci_hydration_policy,
                    crate::serve::OciHydrationPolicy::BodiesBackground
                ) {
                    background_body_refs.push((name, reference));
                }
            }
            Err(error) => {
                completed_refs = completed_refs.saturating_add(1);
                failures = failures.saturating_add(1);
                let message = format!(
                    "Startup OCI manifest prefetch failed for {name}@{reference}: {error:#?}"
                );
                log::warn!("{message}");
                eprintln!("{message}; serving this OCI ref on demand");
            }
        }
    }

    state
        .prefetch_metrics
        .record_startup_oci_execution(StartupOciExecution {
            hydration_policy: oci_hydration_policy.as_str(),
            refs: completed_refs,
            total_unique_blobs,
            inserted,
            failures,
            cold_blobs,
            duration_ms: oci_started_at.elapsed().as_millis() as u64,
        });
    state.prefetch_metrics.record_startup_oci_body_snapshot(
        body_inserted,
        body_failures,
        body_cold_blobs,
        if hydrate_before_ready {
            oci_started_at.elapsed().as_millis() as u64
        } else {
            0
        },
    );

    if matches!(
        oci_hydration_policy,
        crate::serve::OciHydrationPolicy::BodiesBackground
    ) && !background_body_refs.is_empty()
    {
        let background_state = state.clone();
        tokio::spawn(async move {
            let background_started_at = std::time::Instant::now();
            let mut inserted = 0usize;
            let mut failures = 0usize;
            let mut cold_blobs = 0usize;
            for (name, reference) in background_body_refs {
                match crate::serve::http::handlers::manifest::prefetch_manifest_reference(
                    &background_state,
                    &name,
                    &reference,
                    true,
                )
                .await
                {
                    Ok((stats, missing_local_blobs)) => {
                        inserted = inserted.saturating_add(stats.inserted);
                        failures = failures.saturating_add(stats.failures);
                        cold_blobs = cold_blobs.saturating_add(missing_local_blobs);
                    }
                    Err(error) => {
                        failures = failures.saturating_add(1);
                        log::warn!(
                            "Background OCI body hydration failed for {name}@{reference}: {error:#?}"
                        );
                    }
                }
            }
            background_state
                .prefetch_metrics
                .record_startup_oci_body_snapshot(
                    inserted,
                    failures,
                    cold_blobs,
                    background_started_at.elapsed().as_millis() as u64,
                );
        });
    }
}
