"""Portable orchestration/bytes fault injection; never native kernel evidence."""
import ast
import base64
import copy
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import s8_seal_native_once as n
from tests import s8_evidence_export as transport
from tests.test_s8_evidence_export import Producer, complete_report as legacy_report

HEAD = "f" * 40
CID = "a" * 64


def kernel_event(tid, handle=b"abcdefgh"):
    size = 20 + len(handle)
    return n.fence.EVENT.pack(24 + size, 3, 0, 24, 4, -1, tid) + struct.pack("=BBH", 1, 0, size) + b"12345678" + struct.pack("=Ii", len(handle), 1) + handle


def complete_rows():
    rows = [dict(operation="suite_begin", schema=n.SCHEMA, source_sha=HEAD, expected_ids=n.selected_suite()[1])]
    for name in n.selected_suite()[1]:
        rows.append(dict(operation="case_begin", case=name))
        tids = [11] if "test_N01_" in name else [10,10,10] if "test_N02_" in name else [10,11] if any(m in name for m in ("test_N03_", "test_N04_")) else []
        if tids:
            raw = b"".join(kernel_event(tid, b"ijklmnop" if "test_N02_" in name and i else b"abcdefgh") for i,tid in enumerate(tids))
            decoded = [dict(tid=tid, fsid=fid[0].hex(), handle_type=fid[1], handle=fid[2].hex()) for tid,fid in n.fence.metadata_events(raw)]
            rows.append(dict(operation="kernel_fanotify", case=name, group=dict(kind="metadata",owner_tid=10),
                             raw_hex=raw.hex(), byte_count=len(raw), events=decoded, observer_codes=[]))
        if "test_N07_" in name:
            raw = struct.pack("=iIII", 1, 0x8000, 0, 0)
            rows.extend([dict(operation="kernel_inotify",case=name,decoded=n.decode_raw(raw),observer_codes=[]),
                         dict(operation="guard_check_exception",case=name,code="S8_EXECUTION_STOCK_PARENT_EVENT_RED")])
        rows.append(dict(operation="case_end", case=name, status="PASS"))
    rows.append(dict(operation="suite_end", tests=46, skipped=0, failures=0, errors=0, observer_errors=[]))
    return rows


def encode(rows): return b"".join((json.dumps(row,sort_keys=True)+"\n").encode() for row in rows)


class EvidenceTests(unittest.TestCase):
    def test_exact_46_unique_cases_eight_new_and_original_interruption_once(self):
        suite, ids = n.selected_suite()
        self.assertEqual(len(ids),46); self.assertEqual(len(set(ids)),46)
        self.assertEqual(sum(".test_N" in name for name in ids),8)
        self.assertEqual(sum("test_interruption_after_each_anchor_mutation" in name for name in ids),1)
        self.assertTrue(n.evidence_diagnostics(encode(complete_rows()),HEAD)["evidence_complete"])

    def test_legacy_validator_is_not_reinterpreted(self):
        self.assertTrue(transport.evidence_diagnostics(legacy_report())["evidence_complete"])
        self.assertFalse(n.evidence_diagnostics(legacy_report(),HEAD)["evidence_complete"])
        self.assertFalse(transport.evidence_diagnostics(encode(complete_rows()))["evidence_complete"])

    def test_missing_end_partial_json_skip_wrong_source_case_or_kernel_pair_are_hold(self):
        good = complete_rows()
        variants = [good[:-1],good[1:],good[:-2]+good[-1:]]
        for mutate in (lambda r:r[0].update(source_sha="e"*40),
                       lambda r:r[0]["expected_ids"].__setitem__(0,"other"),
                       lambda r:r[-1].update(skipped=1),
                       lambda r:r[-1].update(observer_errors=["OSError"]),
                       lambda r:next(x for x in r if x["operation"]=="kernel_fanotify").update(observer_codes=["UNBOUND"])):
            v=copy.deepcopy(good);mutate(v);variants.append(v)
        variants.append([r for r in good if not(r["operation"]=="kernel_fanotify" and "test_N04_" in r["case"])])
        for rows in variants:
            self.assertFalse(n.evidence_diagnostics(encode(rows),HEAD)["evidence_complete"])
        for raw in (b"",b"{",encode(good)[:-1],b"x"*(transport.MAX_LOG+1)):
            self.assertFalse(n.evidence_diagnostics(raw,HEAD)["evidence_complete"])

    def test_actor_claim_must_match_preserved_kernel_bytes(self):
        rows=complete_rows();row=next(r for r in rows if r["operation"]=="kernel_fanotify")
        row["events"][0]["tid"]=99
        self.assertIn("KERNEL_RAW_DECODE_MISMATCH",n.evidence_diagnostics(encode(rows),HEAD)["codes"])
        row["raw_hex"]="00"
        self.assertFalse(n.evidence_diagnostics(encode(rows),HEAD)["evidence_complete"])

    def test_all_existing_binding_error_fields_fail_closed_even_without_queue_bytes(self):
        for fields in (dict(operation="watch_binding",observation_invalid=True),
                       dict(operation="watch_binding",observation_codes=["WATCH_METADATA_UNAVAILABLE"]),
                       dict(operation="watch_binding_unavailable"),dict(operation="binding_unavailable")):
            rows=complete_rows();rows.insert(-1,fields)
            self.assertIn("OBSERVER_BINDING_RED",n.evidence_diagnostics(encode(rows),HEAD)["codes"])
        for fields in (dict(errors=1),dict(failures=1)):
            rows=complete_rows();rows[-1].update(fields)
            self.assertIn("SUITE_RESULT_RED",n.evidence_diagnostics(encode(rows),HEAD)["codes"])
        rows=complete_rows();next(r for r in rows if r["operation"]=="case_end")["status"]="UNKNOWN"
        self.assertIn("SUITE_RESULT_RED",n.evidence_diagnostics(encode(rows),HEAD)["codes"])

    def test_no_orphan_fork_or_child99_without_first_exception(self):
        rows=complete_rows();rows.insert(-1,dict(operation="fork_parent",caller_pid=1,child_pid=2))
        self.assertIn("CHILD_WAIT_MISSING",n.evidence_diagnostics(encode(rows),HEAD)["codes"])
        rows.insert(-1,dict(operation="child_waited",caller_pid=1,child_pid=2,exit_code=-9))
        self.assertTrue(n.evidence_diagnostics(encode(rows),HEAD)["evidence_complete"])
        rows.insert(-1,dict(operation="child_exit",caller_pid=2,code=99))
        self.assertIn("CHILD99_EXCEPTION_MISSING",n.evidence_diagnostics(encode(rows),HEAD)["codes"])
        rows.insert(-2,dict(operation="child_first_unexpected_exception",caller_pid=2,code="UNKNOWN"))
        self.assertTrue(n.evidence_diagnostics(encode(rows),HEAD)["evidence_complete"])

    def test_new_profile_transport_keeps_raw_and_nonzero_measurement(self):
        raw=encode(complete_rows())
        with tempfile.TemporaryDirectory() as target:
            result,saved=transport.receive_report(Producer(raw),target,99,diagnostics=lambda b:n.evidence_diagnostics(b,HEAD))
            self.assertEqual(saved,raw);self.assertEqual(result["export_exit"],0)
            self.assertTrue(result["evidence_complete"]);self.assertEqual(result["final_exit"],99)
        raw=b'{"operation":"case_first_unexpected_exception","code":"UNKNOWN"}\n{"partial"'
        with tempfile.TemporaryDirectory() as target:
            result,saved=transport.receive_report(Producer(raw),target,1,diagnostics=n.evidence_diagnostics)
            self.assertEqual(saved,raw);self.assertEqual(result["report_state"],"PARTIAL");self.assertEqual(result["final_exit"],1)

    def test_validator_exception_retains_raw_status_and_original_exit(self):
        raw=b'{"preserved":"synthetic bytes"}\n'
        with tempfile.TemporaryDirectory() as target:
            result,saved=transport.receive_report(Producer(raw),target,99,diagnostics=Mock(side_effect=RuntimeError("not copied")))
            self.assertEqual(saved,raw);self.assertEqual(Path(target,"observation.jsonl").read_bytes(),raw)
            self.assertEqual(result["evidence_codes"],["PROFILE_VALIDATOR_ERROR"])
            self.assertEqual(result["final_exit"],99);self.assertEqual(result["export_exit"],0)

    def test_framing_roundtrip_and_mismatch_red(self):
        raw=encode(complete_rows());v=dict(bytes_saved=len(raw),raw_sha256=hashlib.sha256(raw).hexdigest())
        output=io.StringIO()
        with redirect_stdout(output): n.emit(v,raw)
        lines=output.getvalue().splitlines()
        self.assertEqual(lines.count("S8_SEAL_RAW_B64_BEGIN"),1);self.assertEqual(lines.count("S8_SEAL_RAW_B64_END"),1)
        payload="".join(x.removeprefix("S8_SEAL_RAW_B64 ") for x in lines if x.startswith("S8_SEAL_RAW_B64 "))
        self.assertEqual(base64.b64decode(payload,validate=True),raw)
        v["bytes_saved"]+=1
        with self.assertRaises(ValueError):n.emit(v,raw)

    def test_result_stops_on_skip_and_exports_sanitized_first_error(self):
        recorder=Mock();recorder.phase="setup";trace=Mock(recorder=recorder)
        result=n.SealResult(trace);case=unittest.FunctionTestCase(lambda:None)
        result.startTest(case);result.addSkip(case,"not copied private reason");result.stopTest(case)
        self.assertTrue(result.shouldStop);self.assertEqual(result.status[case.id()],"SKIP")
        self.assertNotIn("not copied",str(trace.note.call_args_list))
        try: raise RuntimeError("private free text")
        except RuntimeError: error=sys.exc_info()
        result=n.SealResult(trace);result.startTest(case);result.addError(case,error);result.stopTest(case)
        self.assertNotIn("private free text",str(trace.note.call_args_list))


class ObserverTests(unittest.TestCase):
    def trace(self): return n.SealTrace(Mock(errors=[],phase="test"))
    def test_raw_metadata_read_once_original_result_and_unknown_actor_not_guessed(self):
        trace=self.trace();raw=kernel_event(11);trace.read=Mock(return_value=raw)
        trace.groups[8]=dict(kind="metadata",owner_tid=10)
        with patch.object(n.os,"readlink",return_value="anon_inode:fanotify"):
            self.assertIs(trace.observed_read(8,100),raw)
        trace.read.assert_called_once_with(8,100)
        fields=trace.recorder.note.call_args.kwargs
        self.assertEqual(bytes.fromhex(fields["raw_hex"]),raw)
        self.assertEqual(fields["events"][0]["tid"],11);self.assertEqual(fields["observer_codes"],[])

    def test_original_read_exception_and_fd_reuse_are_unchanged(self):
        trace=self.trace();err=OSError(9,"not copied");trace.read=Mock(side_effect=err)
        with self.assertRaises(OSError) as caught:trace.observed_read(8,100)
        self.assertIs(caught.exception,err);trace.read.assert_called_once()
        trace.groups[8]=dict(kind="metadata");trace.close=Mock()
        trace.observed_close(8);self.assertNotIn(8,trace.groups)

    def test_only_bound_intentional_N07_loss_is_not_observer_corruption(self):
        raw=struct.pack("=iIII",1,0x8000,0,0)
        for bound,negative in ((True,True),(False,True),(True,False)):
            trace=self.trace();trace.read=Mock(return_value=raw)
            trace.case="x.test_N07_parent_namespace_watch_removal_is_red" if negative else "positive"
            if bound:trace.groups[8]=dict(kind="parent",wds=[1])
            with patch.object(n.os,"readlink",return_value="anon_inode:inotify"):trace.observed_read(8,100)
            fields=trace.recorder.note.call_args.kwargs
            self.assertEqual(fields["decoded"]["raw_hex"],raw.hex())
            self.assertTrue(fields["decoded"]["observation_invalid"])
            self.assertEqual(bool(fields["observer_codes"]),not(bound and negative))

    def test_permission_group_bound_before_original_server_liveness_read(self):
        trace=self.trace();instance=SimpleNamespace(fd=8,owner_tid=10)
        def serving(actual):
            self.assertIs(actual,instance)
            self.assertEqual(trace.groups[8],dict(kind="permission",owner_tid=10))
            return "original"
        with patch.object(n.fence.NewJournalFence,"_serve",side_effect=serving) as original,ExitStack() as stack:
            trace.install_seal(stack)
            self.assertEqual(n.fence.NewJournalFence._serve(instance),"original")
            original.assert_called_once_with(instance)

    def test_separate_control_listener_binds_real_return_and_inode_without_replacing_test(self):
        import tests.test_s8_journal_kernel_barrier as module
        trace=self.trace();trace.case="x.test_kernel_flag_seal_does_not_hide_a_chmod_in_the_event_allowlist"
        libc=Mock();libc.inotify_add_watch.return_value=1
        table="inotify wd:1 ino:22 sdev:801 mask:4\n"
        with patch.object(module.ctypes,"CDLL",return_value=libc),ExitStack() as stack:
            trace.install_seal(stack)
            with patch.object(n.Path,"read_text",return_value=table),patch.object(n.os,"stat",return_value=SimpleNamespace(st_dev=os.makedev(8,1),st_ino=0x22)):
                self.assertEqual(module.ctypes.CDLL(None,use_errno=True).inotify_add_watch(8,b"/synthetic",4),1)
            libc.inotify_add_watch.assert_called_once_with(8,b"/synthetic",4)
            self.assertEqual(trace.groups[8],dict(kind="kernel_barrier_control",wds=[1]))
            trace.read=Mock(return_value=struct.pack("=iIII",1,4,0,0))
            with patch.object(n.os,"readlink",return_value="anon_inode:inotify"):trace.observed_read(8,100)
            self.assertEqual(trace.recorder.note.call_args.kwargs["observer_codes"],[])
            trace.case="another_test"
            self.assertIs(module.ctypes.CDLL(None),libc)

    def test_control_listener_wrong_inode_stays_unbound(self):
        import tests.test_s8_journal_kernel_barrier as module
        trace=self.trace();trace.case="x.test_kernel_flag_seal_does_not_hide_a_chmod_in_the_event_allowlist"
        libc=Mock();libc.inotify_add_watch.return_value=1
        with patch.object(module.ctypes,"CDLL",return_value=libc),ExitStack() as stack:
            trace.install_seal(stack)
            with patch.object(n.Path,"read_text",return_value="inotify wd:1 ino:23 sdev:801 mask:4\n"),patch.object(n.os,"stat",return_value=SimpleNamespace(st_dev=os.makedev(8,1),st_ino=0x22)):
                self.assertEqual(module.ctypes.CDLL(None).inotify_add_watch(8,b"/synthetic",4),1)
            self.assertNotIn(8,trace.groups)
            self.assertEqual(trace.recorder.note.call_args.args[0],"binding_unavailable")


class BindingTests(unittest.TestCase):
    def test_manifest_source_files_match_without_self_hash_cycle(self):
        v=n.verify_files();self.assertEqual(set(v["files"]),set(n.SUPPLEMENT)-{"tests/s8_seal_native_binding.json"})
    def test_trigger_is_exact_push_attempt1_no_private_access(self):
        # JSON is a YAML subset: no runtime/CI PyYAML dependency required.
        v=json.loads((n.ROOT/".github/workflows/s8-seal-native-once.yml").read_text())
        self.assertEqual(v["on"],{"push":{"branches":[n.BRANCH]}})
        j=v["jobs"]["seal-native-once"];self.assertEqual(j["runs-on"],"ubuntu-24.04")
        self.assertEqual(j["timeout-minutes"],20);self.assertIn("github.run_attempt == 1",j["if"])
        self.assertNotIn("environment",j);self.assertEqual(v["permissions"],{"contents":"read"})
        text=json.dumps(v);self.assertNotIn("secrets.",text);self.assertNotIn("workflow_dispatch",text)
        self.assertIn("--seal-native-once",text)
    def env(self):return dict(GITHUB_ACTIONS="true",GITHUB_RUN_ATTEMPT="1",GITHUB_EVENT_NAME="push",GITHUB_REPOSITORY="Tausendunde1nz/infra",GITHUB_REF="refs/heads/"+n.BRANCH,GITHUB_SHA=HEAD,GITHUB_RUN_ID="123")
    def test_wrong_event_branch_attempt_repository_or_sha_is_hold(self):
        for key,value in (("GITHUB_EVENT_NAME","workflow_dispatch"),("GITHUB_RUN_ATTEMPT","2"),("GITHUB_REF","refs/pull/240/merge"),("GITHUB_REPOSITORY","other/repo"),("GITHUB_SHA","bad")):
            env=self.env();env[key]=value
            with self.assertRaises(ValueError):n.verify_source(env)
    def test_actual_parent_diff_names_head_message_and_cleanliness_required(self):
        def git(*args):
            if args==("rev-parse","HEAD"):return (HEAD+"\n").encode()
            if args==("rev-parse","HEAD^"):return (n.CANDIDATE+"\n").encode()
            if args==("log","-1","--format=%B"):return (n.MESSAGE+"\n").encode()
            if args[0]=="status":return b""
            if args[:2]==("diff","--name-only"):return ("\n".join(n.SUPPLEMENT)+"\n").encode()
            return b"canonical"
        with patch.object(n,"verify_files"),patch.object(n,"git",side_effect=git),patch.object(n,"CANDIDATE_DIFF",hashlib.sha256(b"canonical").hexdigest()):
            self.assertEqual(n.verify_source(self.env())["head"],HEAD)
            for selected,bad in (("parent",b"c3ca4cb\n"),("message",b"old measurement\n"),("dirty",b" M private\n"),("files",b"private.txt\n")):
                def wrong(*args):
                    if selected=="parent" and args==("rev-parse","HEAD^"):return bad
                    if selected=="message" and args[0]=="log":return bad
                    if selected=="dirty" and args[0]=="status":return bad
                    if selected=="files" and args[:2]==("diff","--name-only"):return bad
                    return git(*args)
                with patch.object(n,"git",side_effect=wrong):
                    with self.assertRaises(ValueError):n.verify_source(self.env())


class LaunchTests(unittest.TestCase):
    def run_launch(self, fault=None):
        calls=[];created=[False];raw=encode(complete_rows())
        if fault=="partial":raw=raw[:-8]
        def command(args,seconds,capture=False):
            calls.append((args,seconds))
            out=""
            if args[:2]==["docker","info"] and args[-1]=="{{.Driver}}":out="other" if fault=="driver" else "overlay2"
            if args[:2]==["docker","create"]:
                created[0]=True;out=CID
                if fault=="create_timeout":raise subprocess.TimeoutExpired(args,seconds)
            if args[:2]==["docker","rm"]:
                if fault=="remove":raise subprocess.CalledProcessError(1,args)
                created[0]=False
            if args[:2]==["docker","stop"] and fault=="stop":raise subprocess.CalledProcessError(1,args)
            if args[:3]==["docker","container","ls"] and "label=tu1nz.s8-seal-main=123" in args and created[0]:out=CID
            if args[:3]==["docker","container","ls"] and "label=tu1nz.s8-seal-main=123" in args and fault=="preexisting":out=CID
            if args[:3]==["docker","container","ls"] and "label=tu1nz.s8-seal-transport=123" in args and fault=="fixture_remains" and any(a[-1]=="tests/test_s8_evidence_export_native.py" for a,_ in calls):out=CID
            if args[:3]==["docker","container","ls"] and "id="+CID in args and created[0]:out=CID
            return SimpleNamespace(stdout=out)
        def run(args,**kwargs):
            calls.append((args,kwargs.get("timeout")))
            if args[-1]=="tests/test_s8_evidence_export_native.py":
                if fault=="transport":raise subprocess.CalledProcessError(1,args)
                self.assertEqual(kwargs["env"]["S8_SEAL_TRANSPORT_OWNER"],"123")
                return SimpleNamespace(returncode=0)
            if fault=="suite_timeout":raise subprocess.TimeoutExpired(args,kwargs["timeout"])
            if fault=="cancel":raise n.LaunchAbort(143)
            return SimpleNamespace(returncode=99 if fault=="suite" else 0)
        def export(cid,destination,measurement,**kwargs):
            calls.append((["EXPORT",cid,measurement],30))
            if fault=="export":raise OSError()
            diagnostic=kwargs["diagnostics"](raw)
            self.assertEqual(diagnostic["evidence_complete"],fault!="partial")
            Path(destination,"observation.jsonl").write_bytes(raw)
            v=dict(bytes_saved=len(raw),raw_sha256=hashlib.sha256(raw).hexdigest(),export_exit=0,evidence_complete=diagnostic["evidence_complete"],final_exit=measurement or 0)
            return v,raw
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,dict(GITHUB_RUN_ID="123",RUNNER_TEMP=tmp),clear=False))
            stack.enter_context(patch.object(n,"verify_source",return_value=dict(head=HEAD)))
            stack.enter_context(patch.object(n.sys,"platform","linux"));stack.enter_context(patch.object(n.os,"geteuid",return_value=1001))
            stack.enter_context(patch.object(n.os,"uname",return_value=SimpleNamespace(machine="x86_64")))
            stack.enter_context(patch.object(n,"command",side_effect=command));stack.enter_context(patch.object(n.subprocess,"run",side_effect=run))
            stack.enter_context(patch.object(n,"docker_export",side_effect=export))
            output=io.StringIO();stack.enter_context(redirect_stdout(output))
            status=n.launch();final=json.loads(next(x.removeprefix("S8_SEAL_FINAL ") for x in output.getvalue().splitlines() if x.startswith("S8_SEAL_FINAL ")))
            self.assertEqual(list(Path(tmp).glob("s8-seal-export-*/final.json"))[0].stat().st_mode&0o777,0o600)
            return status,final,calls
    def test_transport_precedes_single_guest_suite_export_then_cleanup(self):
        status,final,calls=self.run_launch();self.assertEqual(status,0)
        native=next(i for i,(a,_) in enumerate(calls) if a[-1]=="tests/test_s8_evidence_export_native.py")
        create=next(i for i,(a,_) in enumerate(calls) if a[:2]==["docker","create"])
        suite=[i for i,(a,_) in enumerate(calls) if "--guest" in a]
        export=next(i for i,(a,_) in enumerate(calls) if a[0]=="EXPORT")
        stop=next(i for i,(a,_) in enumerate(calls) if a[:2]==["docker","stop"])
        self.assertEqual(len(suite),1);self.assertLess(native,create);self.assertLess(create,suite[0]);self.assertLess(suite[0],export);self.assertLess(export,stop)
        self.assertTrue(final["native_transport_7_zero_skip_cleanup"]);self.assertFalse(final["full_required_CI"])
    def test_transport_red_stops_before_main_guest(self):
        status,final,calls=self.run_launch("transport");self.assertNotEqual(status,0)
        self.assertFalse(any(a[:2]==["docker","create"] for a,_ in calls));self.assertIsNone(final["measurement_exit"])
    def test_suite_failure_timeout_or_cancel_survive_successful_export(self):
        for fault,expected in (("suite",99),("suite_timeout",124),("cancel",143)):
            status,final,calls=self.run_launch(fault);self.assertEqual(status,expected)
            self.assertEqual(final["measurement_exit"],expected);self.assertTrue(any(a[0]=="EXPORT" for a,_ in calls))
    def test_export_failure_or_stop_failure_never_green_and_removal_still_attempted(self):
        for fault in ("export","stop"):
            status,final,calls=self.run_launch(fault);self.assertNotEqual(status,0)
            self.assertTrue(any(a[:2]==["docker","rm"] for a,_ in calls))
    def test_create_timeout_recovers_only_exact_owned_id_then_exports_and_cleans(self):
        status,final,calls=self.run_launch("create_timeout");self.assertEqual(status,124)
        self.assertTrue(any(a[0]=="EXPORT" for a,_ in calls));self.assertTrue(any(a[:2]==["docker","rm"] for a,_ in calls))
    def test_cleanup_absence_unknown_and_malformed_ids_are_not_success(self):
        with patch.object(n,"command",return_value=SimpleNamespace(stdout="unexpected")):
            with self.assertRaises(ValueError):n.owned("synthetic")
        with patch.object(n,"command",side_effect=subprocess.TimeoutExpired("synthetic",10)):
            self.assertIn("CLEANUP_UNVERIFIED",n.cleanup(CID))

    def test_preexisting_owned_label_is_not_adopted_or_removed(self):
        status,final,calls=self.run_launch("preexisting");self.assertNotEqual(status,0)
        self.assertFalse(any(a[:2] in (["docker","create"],["docker","stop"],["docker","rm"]) for a,_ in calls))

    def test_wrong_driver_never_builds_or_executes(self):
        status,final,calls=self.run_launch("driver");self.assertNotEqual(status,0)
        self.assertFalse(any(a[:2]==["docker","create"] or "build" in a for a,_ in calls))

    def test_leftover_transport_is_hold_cleaned_and_no_main_suite(self):
        status,final,calls=self.run_launch("fixture_remains");self.assertNotEqual(status,0)
        self.assertFalse(any("--guest" in a for a,_ in calls));self.assertFalse(final["native_transport_7_zero_skip_cleanup"])
        self.assertTrue(any(a[:2]==["docker","rm"] for a,_ in calls))

    def test_partial_report_or_remove_failure_never_green(self):
        for fault in ("partial","remove"):
            status,final,calls=self.run_launch(fault);self.assertNotEqual(status,0)
            self.assertTrue(any(a[0]=="EXPORT" for a,_ in calls))
            if fault=="remove":self.assertIn("REMOVE_RED",final["cleanup_codes"]);self.assertIn("CONTAINER_REMAINS",final["cleanup_codes"])

    def test_guest_wrong_platform_stops_before_report_creation(self):
        with patch.object(n.sys,"platform","darwin"),patch.object(n.os,"open") as opened:
            self.assertEqual(n.guest(HEAD),74)
        opened.assert_not_called()


if __name__ == "__main__": unittest.main()
