"""Offline regressions for the immutable v2 result; no protected reads."""
import sys
from pathlib import Path
import unittest
BASE=Path(__file__).resolve().parent
sys.path[:0]=[str(BASE),str(BASE/'vendor')]
import bashlex
import tu1nz_backup_notify_v2_engine as e

class ResultBoundaryTests(unittest.TestCase):
    def analyse(self, source):
        bash='/bin/bash' if sys.platform=='darwin' else '/usr/bin/bash'
        return e.analyse(source.encode(),bashlex,bash_check=lambda b:e.shell_syntax(b,bash=bash))
    def test_indented_continuation_reproduces_empty_line_start_coverage(self):
        source='\n'*21+'  printf '+chr(92)+'\n "%s" "fixture"\n'
        r=self.analyse(source)
        self.assertTrue(r['bash_parse_ok']);self.assertTrue(r['structural_parse_ok'])
        site=r['previous_error_coverage']['22']
        self.assertEqual(site['ast_kinds'],[])
        self.assertTrue(site['legacy_line_lexer_error'])
        self.assertIn('LINE_CONTINUATION',site['syntax_forms'])
        self.assertEqual(r['commands'][0]['line'],22)
    def test_no_literal_hits_not_absence_proof(self):
        self.assertEqual(e.caller_decision({'status':'PARSED_COMPLETE'},[],False),'REVIEW_REQUIRED')
    def test_successful_syntax_not_safe_semantics(self):
        r=self.analyse('X=a\nX=b\nunknown_fixture_program "$X"\n')
        self.assertEqual(r['status'],'PARSED_COMPLETE')
        self.assertFalse(r['semantics_complete'])
        self.assertIn('MULTIPLE_STATIC_ASSIGNMENTS',r['semantic_limits'])
        self.assertIn('UNKNOWN_COMMAND_EFFECTS',r['semantic_limits'])
    def test_data_read_not_validation_proof(self):
        r=self.analyse('X=$(cat /opt/telegram_chatbot/.env)\nprintf "%s" "$X"\n')
        self.assertIn('ENV_PARSED_AS_DATA',r['env_facts'])
        self.assertFalse(r['validation_proved'])
        c=dict(hash_matches=True,root=True,active=True,semantic_call=True,resolution_closed=True)
        self.assertEqual(e.caller_decision(r,[c],True),'REVIEW_REQUIRED')
    def test_incomplete_coverage_cannot_authorize_shell_classification(self):
        r=dict(status='INCOMPLETE_ERROR_SITE_COVERAGE',env_facts=['ENV_SOURCED_AS_SHELL'])
        c=dict(hash_matches=True,root=True,active=True,semantic_call=True,resolution_closed=True)
        self.assertEqual(e.caller_decision(r,[c],True),'REVIEW_REQUIRED')

if __name__=='__main__':unittest.main()
