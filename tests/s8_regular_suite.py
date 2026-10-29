"""Finite regular S8 CI collection/result gate, not a measurement launcher.

No observer, event rewrite, new privilege, private input or deadline. The
existing isolated PID1 launcher supplies the unchanged native environment.
Collection-only checks are explicitly NOT execution or native evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

MODULES = (
    "tests.test_s8_anchor", "tests.test_s8_path_policy", "tests.test_s8_execution_contract",
    "tests.test_s8_new_stock", "tests.test_s8_protected_journal", "tests.test_s8_journal_kernel_barrier",
    "tests.test_s8_admission_channel", "tests.test_s8_frozen_entry", "tests.test_s8_execution_observer",
    "tests.test_s8_historical_capacity", "tests.test_s8_history_operator", "tests.test_s8_seal_metadata",
)
CORE_SELECTORS = (
    "tests.test_s8_seal_metadata.NativeSealMetadataTests",
    "tests.test_s8_new_stock.NewStockTests", "tests.test_s8_protected_journal.ProtectedJournalTests",
    "tests.test_s8_journal_kernel_barrier.KernelJournalBarrierTests", "tests.test_s8_path_policy.PathPolicyTests",
    "tests.test_s8_anchor.AnchorNativeTests", "tests.test_s8_admission_channel.AdmissionChannelTests",
    "tests.test_s8_frozen_entry.FrozenEntryTests.test_pid1_loaded_entry_ignores_mutable_control_path",
)
NEW_NATIVE_IDS = tuple("tests.test_s8_seal_metadata.NativeSealMetadataTests." + name for name in (
    "test_N01_prebind_foreign_chmod_restore_is_retained",
    "test_N02_own_append_and_immutable_are_one_use_and_object_bound",
    "test_N03_same_process_foreign_thread_cannot_coalesce_into_owner",
    "test_N04_foreign_process_cannot_coalesce_into_owner",
    "test_N05_owner_chmod_restore_without_flag_transaction_is_red",
    "test_N06_endpoint_transfer_keeps_rename_and_return_detection",
    "test_N07_parent_namespace_watch_removal_is_red",
    "test_N08_lost_metadata_queue_never_becomes_empty_success",
))
EXPECTED_TOTAL = 150  # All 122 original cases plus 20 portable and eight kernel cases.
EXPECTED_CORE = 46
EXPECTED_IDS_SHA256 = "f674599c01bd4c8931c4e53698bf28b27092543c6085f8700e03ac06a7a0b57a"
EXPECTED_CORE_IDS_SHA256 = "fd3ab7da4fec5ad9afe106fe006180bff8cbe81218819b0dc1410aebae3f8f8f"
PUBLIC_CODES = frozenset(("S8_CI_IMPORT_RED", "S8_CI_COLLECTION_RED", "S8_CI_CORE_COLLECTION_RED",
    "S8_CI_NEW_KERNEL_COLLECTION_RED", "S8_CI_SELECTION_BINDING_RED", "S8_CI_CORE_BINDING_RED",
    "S8_CI_ISOLATED_PID1_REQUIRED", "S8_CI_RUNTIME_RED"))


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite): yield from flatten(item)
        else: yield item


def collect(loader=unittest.defaultTestLoader):
    suite = loader.loadTestsFromNames(MODULES)
    cases = list(flatten(suite))
    core = list(flatten(loader.loadTestsFromNames(CORE_SELECTORS)))
    if any(type(test).__name__ == "_FailedTest" for test in (*cases, *core)):
        raise ValueError("S8_CI_IMPORT_RED")
    ids = [test.id() for test in cases]; core_ids = [test.id() for test in core]
    if len(ids) != EXPECTED_TOTAL or len(set(ids)) != len(ids):
        raise ValueError("S8_CI_COLLECTION_RED")
    if len(core_ids) != EXPECTED_CORE or len(set(core_ids)) != len(core_ids) or not set(core_ids) <= set(ids):
        raise ValueError("S8_CI_CORE_COLLECTION_RED")
    actual_new = tuple(sorted(name for name in ids if ".NativeSealMetadataTests." in name))
    if actual_new != NEW_NATIVE_IDS or not set(NEW_NATIVE_IDS) <= set(core_ids):
        raise ValueError("S8_CI_NEW_KERNEL_COLLECTION_RED")
    if hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest() != EXPECTED_IDS_SHA256:
        raise ValueError("S8_CI_SELECTION_BINDING_RED")
    if hashlib.sha256(("\n".join(core_ids) + "\n").encode()).hexdigest() != EXPECTED_CORE_IDS_SHA256:
        raise ValueError("S8_CI_CORE_BINDING_RED")
    return suite, ids, core_ids


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen_ids = []; self.success_ids = []
    def startTest(self, test):
        self.seen_ids.append(test.id()); super().startTest(test)
    def addSuccess(self, test):
        self.success_ids.append(test.id()); super().addSuccess(test)


def evaluate(result, ids, core_ids, new_ids):
    codes = []
    if result.failures: codes.append("S8_CI_ASSERTION_RED")
    if result.errors: codes.append("S8_CI_ERROR_RED")
    if result.skipped: codes.append("S8_CI_SKIP_RED")
    if result.expectedFailures: codes.append("S8_CI_EXPECTED_FAILURE_NOT_PASS")
    if result.unexpectedSuccesses: codes.append("S8_CI_UNEXPECTED_SUCCESS_RED")
    if result.testsRun != len(ids) or result.seen_ids != ids: codes.append("S8_CI_EXECUTION_COVERAGE_RED")
    if len(result.success_ids) != len(ids) or set(result.success_ids) != set(ids): codes.append("S8_CI_NOT_ALL_PASS")
    if not set(core_ids) <= set(result.success_ids): codes.append("S8_CI_CORE_NOT_ALL_PASS")
    if not set(new_ids) <= set(result.success_ids): codes.append("S8_CI_NEW_KERNEL_NOT_ALL_PASS")
    return dict(schema="TU1NZ_S8_REGULAR_CI_SUITE_V1", mode="EXECUTED", expected=len(ids),
        executed=result.testsRun, passed=len(result.success_ids), skipped=len(result.skipped),
        failures=len(result.failures), errors=len(result.errors),
        expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses),
        core_expected=len(core_ids), core_passed=len(set(core_ids) & set(result.success_ids)),
        new_kernel_expected=len(new_ids), new_kernel_passed=len(set(new_ids) & set(result.success_ids)),
        suite_ids_sha256=hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest(),
        codes=codes, verdict="GREEN" if not codes else "HOLD")


def native_platform():
    return (sys.platform == "linux" and os.geteuid() == 0 and os.environ.get("container") == "docker"
            and Path("/.dockerenv").is_file() and Path("/proc/1/comm").read_text().strip() == "systemd")


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        suite, ids, core_ids = collect()
        if args.check:
            value = dict(schema="TU1NZ_S8_REGULAR_CI_SUITE_V1", mode="COLLECTION_ONLY_NOT_NATIVE_PASS",
                expected=len(ids), core_expected=len(core_ids), new_kernel_expected=len(NEW_NATIVE_IDS),
                suite_ids_sha256=hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest(),
                new_kernel_ids=list(NEW_NATIVE_IDS), execution="NOT_RUN_NATIVE_OPEN")
        else:
            if not native_platform(): raise ValueError("S8_CI_ISOLATED_PID1_REQUIRED")
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
            value = evaluate(result, ids, core_ids, NEW_NATIVE_IDS)
    except (OSError, ValueError) as error:
        code = str(error) if type(error) is ValueError and str(error) in PUBLIC_CODES else "S8_CI_RUNTIME_RED"
        value = dict(schema="TU1NZ_S8_REGULAR_CI_SUITE_V1", mode="NOT_COMPLETE", verdict="HOLD", codes=[code])
    print("S8_REGULAR_CI " + json.dumps(value, sort_keys=True), flush=True)
    return 1 if value.get("verdict") == "HOLD" else 0


if __name__ == "__main__": raise SystemExit(main())
