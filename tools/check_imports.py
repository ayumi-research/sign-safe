"""Import every installed sign_safe module, including __main__ and decode/*.py."""
import ast
import importlib
from pathlib import Path
import sys
import sign_safe

root = Path(sign_safe.__file__).resolve().parent
modules = []
for path in sorted(root.rglob("*.py")):
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        names = []
        if isinstance(node, ast.Import):
            names = [item.name.split(".")[0] for item in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            names = [node.module.split(".")[0]]
        assert all(name in sys.stdlib_module_names or name == "sign_safe" for name in names), (path, names)
    parts = list(path.relative_to(root.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    name = ".".join(parts)
    importlib.import_module(name)
    modules.append(name)
    print("OK", name)
print(f"Imported {len(modules)}/{len(modules)} modules; no non-stdlib runtime imports.")
