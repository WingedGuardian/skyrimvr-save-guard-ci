"""Guard decision tests only: authored ordinary files, no fixture execution."""
from pathlib import Path
import ast,copy,hashlib,importlib.util,json,sys,tempfile,unittest
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
        self.entry={'sha256':digest(self.script),'commands':{'Bash':self.command},
                    'tools':['Bash'],'dependencies':{'dependency.py':digest(self.dep)},
                    'home_dependencies':{'admission.py':digest(self.external)},'dependency_closure_complete':True,'cache_tag':sys.implementation.cache_tag}
        self.patches=[patch.object(guard,'ROOT',self.root),patch.object(guard,'REVIEWED_INERT_FIXTURES',{'fixture.py':self.entry}),patch.object(guard.Path,'home',return_value=self.home)]
        self.patches.append(patch.dict(guard.os.environ))
        for item in self.patches:item.start()
        guard.os.environ.pop('RB_HOME',None)
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
        self.external.write_bytes(b'x'*8388609);self.entry['home_dependencies']['admission.py']=digest(self.external)
        self.assertFalse(self.eligible())
    def test_unreviewed_resource_home_or_configuration_refuses(self):
        with patch.dict(guard.os.environ,{'RB_HOME':str(self.base)}):self.assertFalse(self.eligible())
        config=self.home/'.claude/tools/resource-budget/config.json';config.parent.mkdir(parents=True);config.write_text('{}')
        self.assertFalse(self.eligible())
    def test_unreviewed_compatible_bytecode_cache_refuses(self):
        cache=self.script.parent/'__pycache__'/('fixture.'+sys.implementation.cache_tag+'.pyc')
        cache.parent.mkdir();cache.write_bytes(b'unreviewed classifier fixture, never imported')
        self.assertFalse(self.eligible())
    def test_shell_expansion_in_anchor_paths_refuses(self):
        unsafe=self.base/'home$unsafe';unsafe.mkdir();(unsafe/'admission.py').write_bytes(self.external.read_bytes())
        with patch.object(guard.Path,'home',return_value=unsafe):self.assertFalse(self.eligible())
    def test_real_decision_path_keeps_runtime_denials(self):
        # Corpus is classifier input data; nothing in it is dispatched.
        cases=json.loads((HERE/'runtime-controls.json').read_bytes())
        for case in cases:
            with self.subTest(name=case['name']):
                decision=guard.decide({'tool_name':case['tool'],'cwd':str(self.root),'tool_input':case['input']})
                self.assertEqual(decision['kind'],'deny')

class ScopeInvariant(unittest.TestCase):
    def test_legacy_decision_and_reader_paths_change_only_at_call_site(self):
        baseline=ast.parse((HERE.parent/'gateway_guard/inputs/.claude/hooks/protect-save-access.py').read_bytes())
        candidate=ast.parse((HERE/'candidate.py').read_bytes())
        old={n.name:n for n in baseline.body if isinstance(n,ast.FunctionDef)}
        new={n.name:n for n in candidate.body if isinstance(n,ast.FunctionDef)}
        expected=copy.deepcopy(old['decide'])
        calls=[n for n in ast.walk(expected) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='read_only_script_call']
        self.assertEqual(len(calls),1);calls[0].keywords.append(ast.keyword(arg='tool',value=ast.Name(id='tool',ctx=ast.Load())))
        self.assertEqual(ast.dump(expected),ast.dump(new['decide']))
        expected=copy.deepcopy(old['read_only_script_call']);expected.args.args.append(ast.arg(arg='tool'));expected.args.defaults.append(ast.Constant(value=None))
        expected.body.insert(1,ast.parse('if reviewed_inert_fixture_call(script, raw, text, cwd, tool):\n return True').body[0])
        self.assertEqual(ast.dump(expected),ast.dump(new['read_only_script_call']))
    def test_baseline_and_patch_are_exact(self):
        import difflib
        baseline=HERE.parent/'gateway_guard/inputs/.claude/hooks/protect-save-access.py'
        self.assertEqual(digest(baseline),'fe1005c4bab628ec5c35f93e9d180a635bf12a6cd99187284fde2b56564a7ed4')
        expected=''.join(difflib.unified_diff(baseline.read_text().splitlines(keepends=True),(HERE/'candidate.py').read_text().splitlines(keepends=True),'a/protect-save-access.py','b/protect-save-access.py'))
        self.assertEqual((HERE/'candidate.patch').read_text(),expected)
    def test_approval_functions_are_identical_to_baseline(self):
        def selected(path):
            return {n.name:ast.dump(n) for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name in ('run','set_grants')}
        self.assertEqual(selected(HERE/'candidate.py'),selected(HERE.parent/'gateway_guard/inputs/.claude/hooks/protect-save-access.py'))
    def test_production_table_matches_captured_pin_records(self):
        project=json.loads((HERE/'project-pins.json').read_bytes());home=json.loads((HERE/'home-pins.json').read_bytes())['home_dependencies']
        caches=json.loads((HERE/'cache-qualification.json').read_bytes())
        for record in caches['caches']:(home if record['domain']=='home' else project)[record['path']]=record['sha256']
        script,entry=next(iter(guard.REVIEWED_INERT_FIXTURES.items()))
        self.assertEqual(entry['sha256'],project.pop(script));self.assertEqual(entry['dependencies'],project);self.assertEqual(entry['home_dependencies'],home)
        captured=json.loads((HERE/'hook-envelope.json').read_bytes())
        self.assertEqual(entry['tools'],[captured['canonical_hook_tool']])
        self.assertEqual(entry['commands'],{captured['canonical_hook_tool']:captured['command']})
        command=entry['commands']['Bash']
        self.assertTrue(command.startswith('& '))
        self.assertEqual(command.count('-E -s -S -B'),2)
        self.assertIn('run --policy headroom --name delirium-owner-quit --cpu 5 --ram 0.5 --disk C=0.01 --priority below_normal --wait-until-fits 2 --',command)
    def test_only_four_declared_definitions_change(self):
        def definitions(path):
            values={}
            for n in ast.parse(path.read_bytes()).body:
                if isinstance(n,(ast.FunctionDef,ast.ClassDef)):key=n.name
                elif isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name):key=n.targets[0].id
                else:key=ast.dump(n)
                values[key]=ast.dump(n)
            return values
        old=definitions(HERE.parent/'gateway_guard/inputs/.claude/hooks/protect-save-access.py')
        new=definitions(HERE/'candidate.py')
        changed={k for k in old.keys()|new.keys() if old.get(k)!=new.get(k)}
        self.assertEqual(changed,{'REVIEWED_INERT_FIXTURES','reviewed_inert_fixture_call','read_only_script_call','decide'})

class CanonicalEnvelope(unittest.TestCase):
    """Exact production command shape; private external/cache bytes authored.

    This is classifier portability, not execution or real external provenance.
    The independent local real-file probe supplies that separate evidence.
    """
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name).resolve();self.root=(HERE/'inputs').resolve()
        self.script,self.entry=next(iter(copy.deepcopy(guard.REVIEWED_INERT_FIXTURES).items()))
        for name in self.entry['home_dependencies']:
            path=self.home/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('authored nonexecuted external '+name).encode());self.entry['home_dependencies'][name]=digest(path)
        self.created=[]
        for name in self.entry['dependencies']:
            path=self.root/name
            if not path.exists():
                self.assertEqual(path.suffix,'.pyc');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'authored nonexecuted cache');self.created.append(path);self.entry['dependencies'][name]=digest(path)
        self.patches=[patch.object(guard,'ROOT',self.root),patch.object(guard,'REVIEWED_INERT_FIXTURES',{self.script:self.entry}),patch.object(guard.Path,'home',return_value=self.home),patch.dict(guard.os.environ)]
        for item in self.patches:item.start()
        guard.os.environ.pop('RB_HOME',None)
    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        for path in self.created:path.unlink()
        self.temp.cleanup()
    def command(self,tool):return self.entry['commands'][tool].replace('{HOME}',self.home.as_posix()).replace('{ROOT}',self.root.as_posix())
    def observed_command(self):
        captured=json.loads((HERE/'hook-envelope.json').read_bytes())
        return captured['command'].replace('{HOME}',self.home.as_posix()).replace('{ROOT}',self.root.as_posix())
    def test_observed_canonical_bash_powershell_command(self):
        # exec_command is canonicalized to Bash by the host. The configured
        # shell remains PowerShell, so its exact call operator must remain.
        captured=json.loads((HERE/'hook-envelope.json').read_bytes())
        self.assertEqual(captured['canonical_hook_tool'],'Bash')
        self.assertEqual(captured['actual_shell'],'PowerShell')
        self.assertTrue(self.observed_command().startswith('& '))
        self.assertEqual(self.decide(self.observed_command(),'Bash'),'allow')
        # Mutation twin: restore the mistaken Bash-without-call-operator mapping.
        # It must reproduce the exact guard refusal without running the fixture.
        with patch.dict(self.entry['commands'],{'Bash':captured['command'].removeprefix('& ')}):
            self.assertEqual(self.decide(self.observed_command(),'Bash'),'needs_set')
    def test_unobserved_aliases_and_shell_spelling_never_gain_scope(self):
        command=self.observed_command()
        for alias in ('PowerShell','exec_command','functions.exec_command'):
            with self.subTest(alias=alias):self.assertEqual(self.decide(command,alias),'needs_set')
        self.assertEqual(self.decide(command.removeprefix('& '),'Bash'),'needs_set')
    def decide(self,command,tool='Bash'):
        return guard.decide({'tool_name':tool,'cwd':str(self.root),'tool_input':{'command':command}})['kind']
    def test_canonical_wrapped_command_and_empty_registry_control(self):
        for tool in self.entry['tools']:
            command=self.command(tool)
            self.assertEqual(self.decide(command,tool),'allow')
            with patch.object(guard,'REVIEWED_INERT_FIXTURES',{}):self.assertEqual(self.decide(command,tool),'needs_set')
    def test_each_external_pin_drift_revokes_full_command(self):
        command=self.command('Bash')
        for name in self.entry['home_dependencies']:
            path=self.home/name;original=path.read_bytes();path.write_bytes(original+b' drift')
            self.assertEqual(self.decide(command),'needs_set');path.write_bytes(original)
    def test_flags_composition_and_shell_substitution_never_admit(self):
        command=self.command('Bash')
        for other in (command+' extra',command+'; echo x',command.replace('--policy headroom','--policy legacy'),command.replace('--cpu 5','--approved-over-line ram --cpu 5'),command.replace(' -S',''),command.replace('--wait-until-fits 2','--wait-until-fits 200')):
            self.assertNotEqual(self.decide(other),'allow')

if __name__=='__main__':unittest.main(verbosity=2)
