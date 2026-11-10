"""Write controller_freeze_guard/payload-manifest.json from the files as they are now."""
import hashlib
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
here = repo / 'controller_freeze_guard'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


files = ['README.txt', 'qualify.py', 'test_candidate.py', 'project-pins.json', 'candidate.py', 'candidate.patch',
         '.gitattributes']
manifest = {
    'kind': 'controller-freeze-scope-v1',
    'baseline_source': 'readonly_classifier_guard/candidate.py (deployed 2026-11-10 09:29 -05:00, DEPLOY.json)',
    'baseline_sha256': sha(repo / 'readonly_classifier_guard/candidate.py'),
    'expected_new_methods': 14,
    'baseline_red': {'methods': 2, 'failing_assertions': 5, 'errors': 0},
    'reviewed_changed_declarations': ['READ_ONLY_SCRIPT_VERBS', '_bare_single_call', 'read_only_script_call'],
    'review': 'independent read-only review 2026-11-10 (findings 1-3 fixed: test registry built from the guard entry, cd/relative-path rule, write-path modules pinned; 4-6 recorded as limits)',
    'files': {name: sha(here / name) for name in files},
    'supporting_inputs': {name: sha(repo / name) for name in
                          ('.github/workflows/qualify.yml', '.gitattributes', 'gateway_guard/qualify.py',
                           'readonly_classifier_guard/restore-save-backup.py')},
    'referenced_manifests': {name: sha(repo / name) for name in
                             ('gateway_guard/payload-manifest.json', 'inert_fixture_guard/payload-manifest.json',
                              'native_adapter_guard/payload-manifest.json',
                              'readonly_classifier_guard/payload-manifest.json')},
    'native_acceptance': False,
    'limits': [
        'The eleven pinned gateway files are NOT in this repository; CI proves the mechanism on authored stand-ins and that the entry carries exactly the reviewed hashes (project-pins.json). The live decision-only probe at deploy time proves the real bytes.',
        'A freeze argument naming a configured save folder that does not contain the word Saves is a pre-existing _read_only_tail limit shared with every exempt script; the real folders here all contain it.',
        'A relative script token is exempt only as one bare call (allow-list by shape); every composed command must name the script by absolute path. The original 2026-11-10 compound command (here-string + relative controller call) is therefore refused by design; the sanctioned run is two commands with the absolute path. Symlink/junction games on an absolute path are pre-existing for every exempt script.',
        'The local test run on the install is expected to be refused by the installed guard (the test source spells save locations and deletes); results come from CI only.',
        'Cached bytecode (__pycache__/*.cpython-310.pyc) of pinned modules is not pinned; -B stops writing, not reading. Pre-existing for every exempt script; the inert fixture packet pins caches for its own entry.',
        'gateway_test_support/qualification.py (consumed-host pins, read-only by construction) is deliberately not pinned: it must change to admit the newly deployed guard and pinning it here would be circular.',
        'freeze chooses its branch from extra-inputs.json at run time; the non-sampling (40-case) branch loads campaign/fixture modules that are NOT pinned here, so the exemption admits that branch with unreviewed helpers. The intended run is the sampling branch; a later normal-case freeze needs those modules added to the pin.',
        'Tool labels tested are Bash and PowerShell (both in SHELL_TOOLS); Codex reports canonical Bash for exec_command. A list-valued command is not modeled.',
    ],
}
(here / 'payload-manifest.json').write_text(json.dumps(manifest, indent=1) + '\n', encoding='utf-8', newline='\n')
print(json.dumps({k: (v if k != 'files' else len(v)) for k, v in manifest.items() if k in ('baseline_sha256', 'files')}))
