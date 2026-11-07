"""Guard decision tests only: authored ordinary files, no fixture execution."""
from pathlib import Path
import hashlib,importlib.util,json,tempfile,unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('isolated_guard_candidate',HERE/'candidate.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)

class ReviewedCommand(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name).resolve()
        self.root=self.base/'root';self.root.mkdir();self.home=self.base/'home';self.home.mkdir()
        self.script=self.root/'fixture.py';self.script.write_bytes((HERE/'fixture-source.txt').read_bytes())
        self.dep=self.root/'dependency.py';self.dep.write_bytes(b'pass\n')
        self.external=self.home/'admission.py';self.external.write_bytes(b'pass\n')
        self.command='python -B fixture.py'
        self.entry={'sha256':digest(self.script),'command_sha256':hashlib.sha256(self.command.encode()).hexdigest(),
                    'tools':['Bash'],'dependencies':{'dependency.py':digest(self.dep)},
                    'home_dependencies':{'admission.py':digest(self.external)},'dependency_closure_complete':True}
        self.patches=[patch.object(guard,'ROOT',self.root),patch.object(guard,'REVIEWED_INERT_FIXTURES',{'fixture.py':self.entry}),patch.object(guard.Path,'home',return_value=self.home)]
        for item in self.patches:item.start()
    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        self.temp.cleanup()
    def eligible(self,command=None,cwd=None,tool='Bash'):
        return guard.read_only_script_call(self.script,'fixture.py',self.command if command is None else command,str(cwd or self.root),tool=tool)
    def test_exact_eligible(self):self.assertTrue(self.eligible())
    def test_full_decision_baseline_refuses_exact_registry_allows(self):
        payload={'tool_name':'Bash','cwd':str(self.root),'tool_input':{'command':self.command}}
        with patch.object(guard,'REVIEWED_INERT_FIXTURES',{}):self.assertEqual(guard.decide(payload)['kind'],'needs_set')
        self.assertEqual(guard.decide(payload)['kind'],'allow')
        for path in (self.script,self.dep,self.external):
            original=path.read_bytes();path.write_bytes(original+b'# drift\n')
            self.assertEqual(guard.decide(payload)['kind'],'needs_set');path.write_bytes(original)
    def test_composition_arguments_and_other_tools_refuse(self):
        for tail in (' extra','; echo x',' && echo x',' | cat',' > result','\npython other.py'):
            with self.subTest(tail=tail):self.assertFalse(self.eligible(self.command+tail))
        for prefix in ('X=1 ','env ','python -c '):self.assertFalse(self.eligible(prefix+self.command))
        self.assertFalse(self.eligible(tool='Read'));self.assertFalse(self.eligible(cwd=self.base))
    def test_every_dependency_missing_or_changed_revokes(self):
        for path in (self.script,self.dep,self.external):
            original=path.read_bytes()
            path.write_bytes(original+b'# changed\n');self.assertFalse(self.eligible())
            path.unlink();self.assertFalse(self.eligible());path.write_bytes(original)
            self.assertTrue(self.eligible())
    def test_outside_root_and_incomplete_closure_refuse(self):
        self.entry['dependencies']={'../home/admission.py':digest(self.external)};self.assertFalse(self.eligible())
        self.entry['dependencies']={'dependency.py':digest(self.dep)}
        self.entry['home_dependencies']={};self.assertFalse(self.eligible())
        self.entry['home_dependencies']={'admission.py':digest(self.external)}
        self.entry['dependency_closure_complete']=False;self.assertFalse(self.eligible())
    def test_unreviewed_script_never_gains_scope(self):
        with patch.object(guard,'REVIEWED_INERT_FIXTURES',{}):self.assertFalse(self.eligible())
    def test_invalid_schema_reparse_and_budget_refuse(self):
        for invalid in (1,'yes',None):
            self.entry['dependency_closure_complete']=invalid;self.assertFalse(self.eligible())
        self.entry['dependency_closure_complete']=True
        with patch.object(guard.os.path,'islink',side_effect=lambda p:Path(p)==self.script):self.assertFalse(self.eligible())
        self.external.write_bytes(b'x'*2097153);self.entry['home_dependencies']['admission.py']=digest(self.external)
        self.assertFalse(self.eligible())
    def test_real_decision_path_keeps_runtime_denials(self):
        # Corpus is classifier input data; nothing in it is dispatched.
        cases=json.loads((HERE/'runtime-controls.json').read_bytes())
        for case in cases:
            with self.subTest(name=case['name']):
                decision=guard.decide({'tool_name':case['tool'],'cwd':str(self.root),'tool_input':case['input']})
                self.assertEqual(decision['kind'],'deny')

if __name__=='__main__':unittest.main(verbosity=2)
