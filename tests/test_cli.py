from routeros_updater import cli


def test_cli_help_and_version_do_not_contact_router(capsys):
    try:
        cli.main(["--version"])
    except SystemExit as error:
        assert error.code == 0
    assert capsys.readouterr().out.strip() == "0.1.1"


def test_static_doctor_never_connects_to_network(setup, tmp_path, monkeypatch, capsys):
    config, *_ = setup
    for name in ("key", "known_hosts"):
        path = tmp_path / name
        path.write_text("placeholder")
        path.chmod(0o600)
    monkeypatch.setattr(cli, "load", lambda _path: config)

    class ForbiddenRouter:
        def __init__(self, _config):
            raise AssertionError("doctor must not connect")

    monkeypatch.setattr(cli, "Router", ForbiddenRouter)
    assert cli.main(["doctor"]) == 0
    assert '"configuration": "valid"' in capsys.readouterr().out


def test_status_is_offline(setup, monkeypatch, capsys):
    config, *_ = setup
    monkeypatch.setattr(cli, "load", lambda _path: config)
    assert cli.main(["status"]) == 0
    assert '"phase": "idle"' in capsys.readouterr().out


def test_unexpected_exception_does_not_expose_third_party_secrets(monkeypatch, capsys):
    def fail(_path):
        raise RuntimeError("password=TOPSECRET")

    monkeypatch.setattr(cli, "load", fail)
    assert cli.main(["check"]) == 3
    assert "TOPSECRET" not in capsys.readouterr().err
