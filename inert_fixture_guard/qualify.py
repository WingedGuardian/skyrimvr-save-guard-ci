"""Additive exact-candidate qualification; never executes the reviewed fixture."""
from pathlib import Path
import hashlib,importlib.util,json,os,sys,unittest

HERE=Path(__file__).resolve().parent
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main():
    manifest=json.loads((HERE/'payload-manifest.json').read_bytes())
    def verify_packet():
        for name,expected in manifest['files'].items():
            path=HERE/name
            if not path.resolve().is_relative_to(HERE) or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                raise RuntimeError('Candidate packet drift: '+name)
    verify_packet()
    # The pre-existing packet remains frozen and independently qualifies in CI.
    # Reuse its authored save-policy regressions against THIS candidate as well.
    tests=load(HERE/'test_candidate.py','candidate_invariants')
    cases=unittest.defaultTestLoader.loadTestsFromModule(tests)
    outcome=unittest.TextTestRunner(verbosity=2).run(cases)
    if not outcome.wasSuccessful():return 1
    q=load(HERE.parent/'gateway_guard/qualify.py','frozen_regression_qualification')
    q.GUARD=HERE/'candidate.py'
    obsolete={'test_decide_gains_only_the_new_pass','test_only_the_declared_definitions_changed','test_candidate_patch_is_the_exact_diff'}
    retained={name:value for name,value in vars(q.PinTests).items() if name.startswith('test_') and name not in obsolete}
    q.PinTests=type('CandidateAndRetainedChecks',(tests.ScopeInvariant,),retained)
    original=q.load
    def candidate_load(path,name):
        module=original(path,name)
        if hasattr(module,'guard'):
            # Fixture inputs/helper are referenced, not duplicated. No real save
            # paths or native inputs are provided to the regression harness.
            module.guard.ROOT=q.INPUTS
            module.guard.RESTORE_HELPER=HERE/'restore-save-backup.py'
        return module
    q.load=candidate_load
    result=q.main();verify_packet()
    print(json.dumps({'candidate_sha256':hashlib.sha256((HERE/'candidate.py').read_bytes()).hexdigest(),
        'new_classifier_methods':cases.countTestCases(),'retained_legacy_pin_methods':len(retained),
        'candidate_packet_unchanged':True,'private_external_bytes_tested_in_CI':False,
        'blocked_fixture_executed':False,'native_acceptance':False}))
    return result

if __name__=='__main__':raise SystemExit(main())
