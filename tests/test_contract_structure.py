import ast
from pathlib import Path

CONTRACT_PATH = Path(__file__).parents[1] / "contracts" / "vulnproof.py"
SOURCE = CONTRACT_PATH.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def test_contract_has_genlayer_version_pin():
    assert SOURCE.startswith('# { "Depends": "py-genlayer:')


def test_contract_declares_one_contract_class():
    classes = [node for node in TREE.body if isinstance(node, ast.ClassDef)]
    assert [node.name for node in classes] == ["VulnProof"]


def test_required_public_methods_exist():
    class_node = next(node for node in TREE.body if isinstance(node, ast.ClassDef))
    names = {node.name for node in class_node.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert {
        "__init__",
        "submit_report",
        "get_report",
        "get_report_count",
        "verify_report",
        "dispute_report",
    }.issubset(names)


def test_consensus_and_web_access_are_used():
    assert "gl.nondet.web.render" in SOURCE
    assert "gl.nondet.exec_prompt" in SOURCE
    assert "gl.vm.run_nondet_unsafe" in SOURCE
    assert "def validator_fn(leader_result)" in SOURCE


def test_report_statuses_and_storage_are_explicit():
    assert "TreeMap[u256, str]" in SOURCE
    for status in ("verified", "rejected", "disputed", "unresolved", "submitted"):
        assert f'"{status}"' in SOURCE


def test_python_syntax_parses():
    compile(SOURCE, str(CONTRACT_PATH), "exec")
