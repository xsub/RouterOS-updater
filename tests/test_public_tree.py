import importlib.util
from pathlib import Path, PurePosixPath

_spec = importlib.util.spec_from_file_location(
    "public_tree_check", Path(__file__).resolve().parents[1] / "tools" / "check_public_tree.py"
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
violations = _module.violations


def test_public_example_can_use_documentation_domains_and_fictional_private_addresses():
    assert not violations(
        PurePosixPath("examples/router1.toml"),
        b'host = "10.42.0.1"\ndns_name = "service.example.test"\n',
    )


def test_raw_reports_and_private_configuration_are_not_publishable():
    assert violations(PurePosixPath("docs/test-results.xml"), b"test report")
    assert violations(PurePosixPath("local/router.toml"), b"private configuration")
    assert violations(PurePosixPath("state.json"), b"runtime state")


def test_personal_machine_paths_are_not_publishable():
    fake_home = "/" + "Users" + "/" + "fictional-user" + "/" + "source.py"
    assert "personal home path" in violations(PurePosixPath("docs/example.md"), fake_home.encode())


def test_private_keys_and_tokens_are_not_publishable():
    fake_key = b"-----" + b"BEGIN OPENSSH PRIVATE KEY-----\n"
    fake_token = b"ghp_" + b"A" * 40
    assert "private key" in violations(PurePosixPath("src/example.py"), fake_key)
    assert "access token" in violations(PurePosixPath("src/example.py"), fake_token)
