from dataclasses import replace
from datetime import timedelta

import pytest

from routeros_updater.engine import Engine
from routeros_updater.errors import IdentityError, PolicyError, TransportError


def apply_plan(engine):
    plan = engine.plan()
    assert plan["ready"], plan["reasons"]
    return engine.apply(plan["id"])


def test_complete_update_backs_up_both_sides_and_reboots_exactly_twice(setup):
    config, _, router, store, engine = setup
    result = apply_plan(engine)
    assert result["phase"] == "complete"
    assert router.calls.count("reboot") == 2
    assert router.calls.count("flash") == 1
    assert router.calls.index("backup-pre") < router.calls.index("download")
    assert router.calls.index("backup-post") > router.calls.index("flash")
    assert result["result"]["version"] == result["result"]["firmware"] == "7.24.7"
    assert (store.root / "backups" / result["run_id"] / "pre" / "manifest.json").is_file()
    assert config.policy.auto_apply is False


def test_firmware_only_update_reboots_once(setup):
    _, _, router, _, engine = setup
    router.target = router.current.version
    router.current = replace(router.current, firmware="7.24.5")
    result = apply_plan(engine)
    assert result["phase"] == "complete"
    assert "download" not in router.calls
    assert router.calls.count("flash") == router.calls.count("reboot") == 1


def test_check_never_downloads_or_reboots(setup):
    _, _, router, _, engine = setup
    assert engine.run()["phase"] == "planned"
    assert not any(name in router.calls for name in ("download", "flash", "reboot"))


def test_auto_timer_can_apply_without_manual_plan_id(setup):
    config, clock, router, store, _ = setup
    config = replace(config, policy=replace(config.policy, auto_apply=True))
    engine = Engine(config, store, router, clock=clock, checks=lambda: {"office": True})
    assert engine.run()["phase"] == "complete"


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"version": "6.49.20", "packages": {"routeros": "6.49.20"}}, "7.23"),
        ({"auto_upgrade": True}, "auto-upgrade"),
        ({"npk_files": ["unknown.npk"]}, "pending"),
        ({"scheduled": True}, "pending"),
        ({"free_disk": 1}, "storage"),
        ({"free_memory": 1}, "storage"),
        ({"channel": "testing"}, "channel"),
        ({"disabled_packages": ["container"]}, "Disabled"),
        ({"packages": {"routeros": "7.24.5"}}, "inconsistent"),
    ],
)
def test_preflight_blocks_unsafe_router_states(setup, change, reason):
    _, _, router, _, engine = setup
    router.current = replace(router.current, **change)
    plan = engine.plan()
    assert not plan["ready"]
    assert any(reason in item for item in plan["reasons"])
    assert "download" not in router.calls


@pytest.mark.parametrize("target", ["7.24.5", "8.0", "7.26beta1"])
def test_no_downgrade_major_or_prerelease(setup, target):
    _, _, router, _, engine = setup
    router.target = target
    if "beta" in target:
        with pytest.raises(PolicyError):
            engine.plan()
    else:
        assert not engine.plan()["ready"]


def test_age_is_persisted_and_respected_after_controller_restart(setup):
    config, clock, router, store, _ = setup
    config = replace(config, policy=replace(config.policy, minimum_observation_hours=72))
    engine = Engine(config, store, router, clock=clock, checks=lambda: {"office": True})
    assert not engine.plan()["ready"]
    clock.sleep(72 * 3600)
    restarted = Engine(config, store, router, clock=clock, checks=lambda: {"office": True})
    assert restarted.plan()["ready"]


def test_expired_plan_is_never_applied(setup):
    _, clock, router, _, engine = setup
    plan = engine.plan()
    clock.sleep(3601)
    with pytest.raises(PolicyError, match="expired"):
        engine.apply(plan["id"])
    assert "backup-pre" not in router.calls


def test_changed_target_and_package_inventory_invalidate_plan(setup):
    _, _, router, _, engine = setup
    plan = engine.plan()
    router.target = "7.24.8"
    with pytest.raises(PolicyError, match="target changed"):
        engine.apply(plan["id"])
    assert "download" not in router.calls


def test_failed_backup_prevents_download(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    router.fail_backup = True
    with pytest.raises(TransportError):
        engine.apply(plan["id"])
    assert "download" not in router.calls
    assert store.read()["phase"] == "attention"
    assert "7.24.7" in store.read()["blocked"]


def test_no_reboot_effect_enters_attention_without_a_second_attempt(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    router.reboot_effect = False
    with pytest.raises(PolicyError, match="restart could not"):
        engine.apply(plan["id"])
    assert router.calls.count("reboot") == 1
    with pytest.raises(PolicyError, match="reconciliation"):
        engine.run()
    assert router.calls.count("reboot") == 1
    assert store.read()["phase"] == "attention"


def test_expected_disconnect_on_reboot_is_observed_not_reissued(setup):
    _, _, router, _, engine = setup
    router.disconnect_reboot = True
    assert apply_plan(engine)["phase"] == "complete"
    assert router.calls.count("reboot") == 2


def test_interrupted_flash_is_never_repeated(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    router.crash_at = "flash"
    with pytest.raises(KeyboardInterrupt):
        engine.apply(plan["id"])
    assert store.read()["phase"] == "boot_flash_intent"
    with pytest.raises(PolicyError, match="ambiguous"):
        engine.run()
    assert router.calls.count("flash") == 1
    assert store.read()["phase"] == "attention"


def test_crash_before_reboot_command_requires_observation_and_never_reissues(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    router.crash_at = "reboot"
    with pytest.raises(KeyboardInterrupt):
        engine.apply(plan["id"])
    assert store.read()["phase"] == "ros_reboot_intent"
    with pytest.raises(PolicyError, match="restart could not"):
        engine.run()
    assert router.calls.count("reboot") == 1


def test_crash_after_first_reboot_resumes_and_finishes(setup):
    config, clock, router, store, engine = setup
    plan = engine.plan()
    original = router.reboot
    once = [False]

    def reboot():
        original()
        if not once[0]:
            once[0] = True
            raise KeyboardInterrupt()

    router.reboot = reboot
    with pytest.raises(KeyboardInterrupt):
        engine.apply(plan["id"])
    resumed = Engine(config, store, router, clock=clock, checks=lambda: {"office": True})
    assert resumed.run()["phase"] == "complete"
    assert router.calls.count("reboot") == 2


def test_unhealthy_services_stop_before_routerboot(setup):
    config, clock, router, store, engine = setup
    plan = engine.plan()
    engine.checks = lambda: {"office": router.current.version != router.target}
    with pytest.raises(PolicyError, match="health"):
        engine.apply(plan["id"])
    assert router.calls.count("reboot") == 1
    assert "flash" not in router.calls
    assert store.read()["phase"] == "attention"


def test_no_mutations_outside_window(setup):
    _, clock, router, _, engine = setup
    clock.start += timedelta(hours=8)
    plan = engine.plan()
    with pytest.raises(PolicyError, match="window"):
        engine.apply(plan["id"])
    assert "backup-pre" not in router.calls


def test_changed_config_during_resume_does_not_repeat_any_operation(setup):
    config, clock, router, store, engine = setup
    plan = engine.plan()
    router.crash_at = "reboot"
    with pytest.raises(KeyboardInterrupt):
        engine.apply(plan["id"])
    config = replace(config, policy=replace(config.policy, channel="stable"))
    new = Engine(config, store, router, clock=clock)
    with pytest.raises(PolicyError, match="Configuration changed"):
        new.run()
    assert router.calls.count("reboot") == 1


def test_reconcile_requires_health_and_keeps_failed_target_blocked(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    router.fail_backup = True
    with pytest.raises(TransportError):
        engine.apply(plan["id"])
    run_id = store.read()["run_id"]
    assert engine.acknowledge(run_id, "Operator verified no changes were applied")["blocked"] == [
        "7.24.7"
    ]
    assert (store.root / "history" / f"{run_id}.json").is_file()
    assert not engine.plan()["ready"]


def test_wrong_identity_during_reboot_is_not_treated_as_transient_failure(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    original = router.reboot

    def reboot():
        original()
        router.current = replace(router.current, serial="OTHER-ROUTER")

    router.reboot = reboot
    with pytest.raises(IdentityError):
        engine.apply(plan["id"])
    assert store.read()["phase"] == "attention"
    assert "flash" not in router.calls


def test_tampered_backup_is_detected(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    router.crash_at = "reboot"
    with pytest.raises(KeyboardInterrupt):
        engine.apply(plan["id"])
    state = store.read()
    state["phase"] = "downloaded"
    store.save(state)
    (store.root / "backups" / state["run_id"] / "pre" / "router.backup").write_bytes(b"tampered")
    with pytest.raises(PolicyError, match="backup"):
        engine.run()
    assert router.calls.count("reboot") == 1


def test_ambiguous_download_is_observed_without_resending(setup):
    _, _, router, _, engine = setup
    original = router.download

    def download():
        original()
        raise TransportError("Connection lost after download dispatch")

    router.download = download
    assert apply_plan(engine)["phase"] == "complete"
    assert router.calls.count("download") == 1


def test_backup_secret_rotation_during_transaction_stops_before_restart(setup):
    config, _, router, store, engine = setup
    plan = engine.plan()
    original = router.download

    def download():
        original()
        from pathlib import Path

        Path(config.backup_password_file).write_text("a-different-encryption-password-long-enough")

    router.download = download
    with pytest.raises(PolicyError, match="credential changed"):
        engine.apply(plan["id"])
    assert "reboot" not in router.calls
    assert store.read()["phase"] == "attention"


def test_near_end_of_window_timer_waits_without_creating_a_run(setup):
    config, clock, router, store, _ = setup
    config = replace(config, policy=replace(config.policy, auto_apply=True))
    clock.start += timedelta(minutes=115)
    engine = Engine(config, store, router, clock=clock, checks=lambda: {"office": True})
    result = engine.run()
    assert result["phase"] == "planned"
    assert "waiting" in result
    assert store.read()["phase"] == "idle"
    assert "backup-pre" not in router.calls


def test_supported_allowlist_and_minor_policies(setup):
    config, clock, router, store, _ = setup
    router.target = "7.25.2"
    config = replace(
        config, policy=replace(config.policy, allow_minor=False, allowed_versions=["7.24.7"])
    )
    engine = Engine(config, store, router, clock=clock, checks=lambda: {"office": True})
    result = engine.plan()
    assert not result["ready"]
    assert any("Minor" in reason for reason in result["reasons"])
    assert any("allowlist" in reason for reason in result["reasons"])


@pytest.mark.parametrize(
    "mode,certificate",
    [("http", "yes"), ("https", "no"), ("https", "yes-without-crl"), ("unknown", "unknown")],
)
def test_unverified_download_transport_blocks_plan_and_does_not_contact_update_server(
    setup, mode, certificate
):
    _, _, router, _, engine = setup
    router.current = replace(router.current, update_mode=mode, update_certificate=certificate)
    result = engine.plan()
    assert not result["ready"]
    assert any("check-certificate=yes" in item for item in result["reasons"])
    assert "check" not in router.calls
    assert "download" not in router.calls


def test_transport_downgrade_after_plan_is_rejected_before_backup(setup):
    _, _, router, _, engine = setup
    plan = engine.plan()
    router.current = replace(router.current, update_certificate="no")
    with pytest.raises(PolicyError, match="check-certificate"):
        engine.apply(plan["id"])
    assert "backup-pre" not in router.calls


def test_rotated_backup_password_stops_before_flash(setup):
    config, _, router, store, engine = setup
    plan = engine.plan()
    original = router.reboot

    def reboot():
        original()
        from pathlib import Path

        Path(config.backup_password_file).write_text("replacement-password-at-least-24")

    router.reboot = reboot
    with pytest.raises(PolicyError, match="credential changed"):
        engine.apply(plan["id"])
    assert "flash" not in router.calls
    assert store.read()["phase"] == "attention"


def test_complete_pre_backup_survives_controller_crash_without_being_recreated(setup):
    _, _, router, store, engine = setup
    plan = engine.plan()
    original = router.backup
    once = [False]

    def backup(destination, snapshot):
        result = original(destination, snapshot)
        if not once[0]:
            once[0] = True
            raise KeyboardInterrupt()
        return result

    router.backup = backup
    with pytest.raises(KeyboardInterrupt):
        engine.apply(plan["id"])
    assert store.read()["phase"] == "prepared"
    assert engine.run()["phase"] == "complete"
    assert router.calls.count("backup-pre") == 1


def test_ambiguous_download_is_observed_without_reissuing(setup):
    _, _, router, _, engine = setup
    original = router.download

    def download():
        original()
        raise TransportError("Lost SSH after sending download")

    router.download = download
    assert apply_plan(engine)["phase"] == "complete"
    assert router.calls.count("download") == 1


def test_clock_stopping_does_not_remove_reboot_timeout(setup):
    _, clock, router, store, engine = setup
    now = clock.now()
    clock.now = lambda: now
    router.reboot_effect = False
    with pytest.raises(PolicyError, match="restart could not"):
        apply_plan(engine)
    assert router.calls.count("reboot") == 1
    assert store.read()["phase"] == "attention"
