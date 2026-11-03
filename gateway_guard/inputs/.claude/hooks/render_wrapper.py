"""Render save-access-entry.template.ps1 into the deployable wrapper: the interpreter path is the only substitution.

The template is what CI tests (rendered there with the runner's interpreter); the deployed file is the same bytes
with the pinned local interpreter. The pin is an ABSOLUTE path (CI 049a90e requires it) and must not contain a
double quote, which the PowerShell single-quoted literal cannot carry safely into the Arguments string.

    python render_wrapper.py <template> <python_path> <out>
"""
import sys
from pathlib import Path

PLACEHOLDER = '__GUARD_PYTHON__'


def render(template_text, python_path):
    if '"' in python_path or "'" in python_path or '\n' in python_path:
        raise ValueError('interpreter path may not contain quotes or newlines')
    if not Path(python_path).is_absolute():
        raise ValueError('interpreter path must be absolute')
    if template_text.count(PLACEHOLDER) != 1:
        raise ValueError('template must contain the placeholder exactly once')
    return template_text.replace(PLACEHOLDER, python_path.replace('\\', '/'))


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    template, python_path, out = argv[1:]
    text = render(Path(template).read_text(encoding='utf-8'), python_path)
    Path(out).write_text(text, encoding='utf-8', newline='\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
