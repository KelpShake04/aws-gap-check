"""테스트가 backend/, scanner/, scripts/의 모듈을 import할 수 있게 경로를 잡는다.

실행: 레포 루트에서 `python -m unittest -v`
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

for sub in ("backend", "scanner", "scripts"):
    path = str(ROOT / sub)
    if path not in sys.path:
        sys.path.insert(0, path)
