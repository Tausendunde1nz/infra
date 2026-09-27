import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parent
# Repository tests use only the pinned vendor directory, never an installed package.
sys.path.insert(0,str(BASE))
sys.path.insert(0,str(BASE/'vendor'))
import bashlex
import tu1nz_backup_notify_v2_engine as e

class SyntaxTests(unittest.TestCase):
    def setUp(self):
        if sys.platform=='darwin':
            original=e.shell_syntax
            patcher=patch.object(e,'shell_syntax',lambda s:original(s,bash='/bin/bash'))
            patcher.start();self.addCleanup(patcher.stop)

    def check(self,text):return e.analyse(text.encode(),bashlex)
    def test_multiline_double_quote(self):
        self.assertEqual(self.check('message="one\ntwo\nthree"\nprintf "%s" "$message"\n')['status'],'PARSED_COMPLETE')
    def test_multiline_single_quote(self):
        self.assertEqual(self.check("x='first\nsecond'\nprintf '%s' \"$x\"\n")['status'],'PARSED_COMPLETE')
    def test_continuation(self):
        self.assertEqual(self.check('printf \\\n "%s" \\\n "text"\n')['status'],'PARSED_COMPLETE')
    def test_line_coverage_22_23_29(self):
        source='\n'*20+'x="first\nsecond\nthird\n'+'fourth\n'*5+'last"\nprintf "%s" "$x"\n'
        result=self.check(source)
        self.assertEqual(result['status'],'PARSED_COMPLETE')
        for n in ('22','23','29'):self.assertTrue(result['previous_error_coverage'][n]['multiline'])
    def test_heredoc(self):
        self.assertEqual(self.check('cat <<EOF\nfixture data\nEOF\n')['status'],'PARSED_COMPLETE')
    def test_unterminated_quote(self):self.assertEqual(self.check('echo "unfinished')['status'],'SYNTAX_REJECTED')
    def test_unterminated_heredoc(self):self.assertNotEqual(self.check('cat <<EOF\nbody\n')['status'],'PARSED_COMPLETE')
    def test_source(self):
        for x in ('source','.'):self.assertIn('ENV_SOURCED_AS_SHELL',self.check(x+' '+e.ENV_PATH)['env_facts'])
    def test_source_via_static_path(self):self.assertIn('ENV_SOURCED_AS_SHELL',self.check('E='+e.ENV_PATH+'\n. "$E"\n')['env_facts'])
    def test_eval_taint(self):
        result=self.check('V=$(cat '+e.ENV_PATH+')\neval "$V"\n')
        self.assertIn('ENV_SOURCED_AS_SHELL',result['env_facts'])
    def test_shell_c_taint(self):
        for shell in ('bash','sh'):
            result=self.check('V=$(cat '+e.ENV_PATH+')\n'+shell+' -c "$V"\n')
            self.assertIn('ENV_SOURCED_AS_SHELL',result['env_facts'])
    def test_unquoted_taint(self):
        self.assertIn('ENV_VALUES_REACH_ARGUMENT_BOUNDARIES',self.check('V=$(cat '+e.ENV_PATH+')\nprintf %s $V\n')['env_facts'])
    def test_quoted_data_not_shell(self):
        result=self.check('V=$(grep "^SAFE_KEY=" '+e.ENV_PATH+' | cut -d= -f2-)\nprintf "%s" "$V"\n')
        self.assertIn('ENV_PARSED_AS_DATA',result['env_facts']);self.assertIn('ENV_VALUES_REACH_FIXED_ARGUMENT',result['env_facts']);self.assertNotIn('ENV_SOURCED_AS_SHELL',result['env_facts'])
    def test_indirect_fail_closed(self):self.assertNotEqual(self.check('echo "${!key}"\n')['status'],'PARSED_COMPLETE')
    def test_arrays_fail_closed(self):self.assertNotEqual(self.check('x=(a b)\n')['status'],'PARSED_COMPLETE')
    def test_double_bracket_fail_closed(self):self.assertNotEqual(self.check('[[ -f /x ]]\n')['status'],'PARSED_COMPLETE')
    def test_process_substitution_and_function(self):self.assertEqual(self.check('f() { cat <(printf fixture); }\nf\n')['status'],'PARSED_COMPLETE')
    def test_subshell(self):self.assertEqual(self.check('( printf fixture )\n')['status'],'PARSED_COMPLETE')
    def test_disagreement(self):self.assertEqual(e.analyse(b'echo ok',bashlex,bash_check=lambda s:False)['status'],'PARSER_DISAGREEMENT')
    def test_missing_ast(self):
        class Broken:
            @staticmethod
            def parse(s):return []
        self.assertNotEqual(e.analyse(b'echo ok',Broken)['status'],'PARSED_COMPLETE')
    def test_secret_redaction(self):
        import json
        secret='CANARY_ABSOLUTELY_PRIVATE_VALUE'
        self.assertNotIn(secret,json.dumps(self.check('x="'+secret+'"\nprintf "%s" "$x"\n')))
    def test_parse_mode_does_not_execute(self):
        with tempfile.TemporaryDirectory() as p:
            marker=Path(p)/'MUST_NOT_EXIST'
            source='x=$(touch '+str(marker)+')\ntouch '+str(marker)+'\n'
            self.assertEqual(self.check(source)['status'],'PARSED_COMPLETE');self.assertFalse(marker.exists())
    def test_source_never_opened(self):
        with tempfile.TemporaryDirectory() as p:
            nonexistent=str(Path(p)/'.env')
            self.assertEqual(self.check('. '+nonexistent+'\n')['status'],'PARSED_COMPLETE');self.assertFalse(Path(nonexistent).exists())

class CallerTests(unittest.TestCase):
    def test_path_lookup_is_not_closed(self):
        self.assertEqual(e.direct_callers(b'backup_notify.sh\n',bashlex)['status'],'REVIEW_REQUIRED')
    def test_exec(self):self.assertEqual(e.direct_callers((e.TARGET+'\n').encode(),bashlex)['calls'][0]['kind'],'EXEC')
    def test_text_not_call(self):self.assertFalse(e.direct_callers(('echo '+e.TARGET+'\n# '+e.TARGET+'\n').encode(),bashlex)['calls'])
    def test_cron_root(self):
        r=e.caller_fragments(('0 1 * * * root '+e.TARGET+'\n').encode(),'/etc/cron.d/example',bashlex)
        self.assertTrue(r['fragments'][0]['root']);self.assertTrue(r['fragments'][0]['calls'])
    def test_systemd_prefix(self):
        r=e.caller_fragments(('ExecStart=+'+e.TARGET+'\n').encode(),'/etc/systemd/system/example.service',bashlex)
        self.assertTrue(r['fragments'][0]['force_root']);self.assertTrue(r['fragments'][0]['calls'])
    def test_hash_mismatch(self):self.assertEqual(e.caller_decision({},[dict(hash_matches=False)],True),'REVIEW_REQUIRED')
    def test_no_active_needs_closure(self):
        self.assertEqual(e.caller_decision({},[],False),'REVIEW_REQUIRED');self.assertEqual(e.caller_decision({},[],True),'NO_ACTIVE_CALLER')
    def test_active_unsafe(self):
        proof=dict(status='PARSED_COMPLETE',env_facts=['ENV_SOURCED_AS_SHELL'])
        self.assertEqual(e.caller_decision(proof,[dict(hash_matches=True,root=True,active=True,semantic_call=True,resolution_closed=True)]),'ACTIVE_ROOT_SHELL_EVALUATION')
    def test_inactive(self):
        self.assertEqual(e.caller_decision({},[dict(hash_matches=True,root=True,active=False,semantic_call=True)],True),'NO_ACTIVE_CALLER')
    def test_safe_parser_requires_validation(self):
        proof=dict(status='PARSED_COMPLETE',env_facts=['ENV_PARSED_AS_DATA'],semantics_complete=True,validation_proved=True)
        caller=[dict(hash_matches=True,root=True,active=True,semantic_call=True,resolution_closed=True)]
        self.assertEqual(e.caller_decision(proof,caller),'ACTIVE_SAFE_DATA_PARSER')
        proof['validation_proved']=False;self.assertEqual(e.caller_decision(proof,caller),'REVIEW_REQUIRED')

if __name__=='__main__':unittest.main()
