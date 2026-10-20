# Unit test results

```text
test_http_errors_do_not_expose_remote_bodies (test_triage.CredentialTests.test_http_errors_do_not_expose_remote_bodies) ... ok
test_known_key_and_headers_are_redacted_but_usage_is_preserved (test_triage.CredentialTests.test_known_key_and_headers_are_redacted_but_usage_is_preserved) ... ok
test_package_allowlist_excludes_secret_pdf_and_local_env (test_triage.CredentialTests.test_package_allowlist_excludes_secret_pdf_and_local_env) ... ok
test_absent_prerequisite_short_circuits_irrelevant_unknown (test_triage.PolicyTests.test_absent_prerequisite_short_circuits_irrelevant_unknown) ... ok
test_all_six_rules (test_triage.PolicyTests.test_all_six_rules) ... ok
test_conflicts_require_review (test_triage.PolicyTests.test_conflicts_require_review) ... ok
test_firmware_boundaries_and_product_specificity (test_triage.PolicyTests.test_firmware_boundaries_and_product_specificity) ... ok
test_inconsistent_path_is_validation_review_not_low (test_triage.PolicyTests.test_inconsistent_path_is_validation_review_not_low) ... ok
test_invalid_boolean_is_rejected (test_triage.PolicyTests.test_invalid_boolean_is_rejected) ... ok
test_unknown_decisive_facts_do_not_default_to_safe (test_triage.PolicyTests.test_unknown_decisive_facts_do_not_default_to_safe) ... ok
test_unknown_internet_is_not_internal (test_triage.PolicyTests.test_unknown_internet_is_not_internal) ... ok
test_duke_request_supports_native_tools_and_private_auth (test_triage.ProviderProtocolTests.test_duke_request_supports_native_tools_and_private_auth) ... ok
test_auto_fallback_records_attempts_and_cache_mode (test_triage.WorkflowTests.test_auto_fallback_records_attempts_and_cache_mode) ... ok
test_conflicting_snapshot_retains_both_records (test_triage.WorkflowTests.test_conflicting_snapshot_retains_both_records) ... ok
test_controlled_failure_has_two_attempts_and_no_false_safety (test_triage.WorkflowTests.test_controlled_failure_has_two_attempts_and_no_false_safety) ... ok
test_cross_scope_query_rejected_before_execution (test_triage.WorkflowTests.test_cross_scope_query_rejected_before_execution) ... ok
test_duplicate_query_rejected (test_triage.WorkflowTests.test_duplicate_query_rejected) ... ok
test_environment_without_provenance_is_rejected (test_triage.WorkflowTests.test_environment_without_provenance_is_rejected) ... ok
test_failed_model_setup_still_saves_explicit_failure (test_triage.WorkflowTests.test_failed_model_setup_still_saves_explicit_failure) ... ok
test_invalid_tool_never_executes_and_correction_can_finish (test_triage.WorkflowTests.test_invalid_tool_never_executes_and_correction_can_finish) ... ok
test_kev_failure_does_not_change_supported_rating (test_triage.WorkflowTests.test_kev_failure_does_not_change_supported_rating) ... ok
test_live_failure_preserves_attempt_history_without_cache (test_triage.WorkflowTests.test_live_failure_preserves_attempt_history_without_cache) ... ok
test_live_kev_saves_full_catalog_with_original_hash (test_triage.WorkflowTests.test_live_kev_saves_full_catalog_with_original_hash) ... ok
test_model_synthesis_cannot_invent_claims_or_change_rating (test_triage.WorkflowTests.test_model_synthesis_cannot_invent_claims_or_change_rating) ... ok
test_original_baseline_preserves_unknowns (test_triage.WorkflowTests.test_original_baseline_preserves_unknowns) ... ok
test_positive_replay_with_correlated_tools_and_saved_inputs (test_triage.WorkflowTests.test_positive_replay_with_correlated_tools_and_saved_inputs) ... ok
test_source_cache_tampering_is_not_accepted (test_triage.WorkflowTests.test_source_cache_tampering_is_not_accepted) ... ok
test_source_instructions_do_not_become_tools_or_policy (test_triage.WorkflowTests.test_source_instructions_do_not_become_tools_or_policy) ... ok
test_tool_budget_stops_and_reports_review (test_triage.WorkflowTests.test_tool_budget_stops_and_reports_review) ... ok

----------------------------------------------------------------------
Ran 29 tests in 0.560s

OK
```
