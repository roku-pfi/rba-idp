"""Passkeys survive a cloud teardown (rba_idp.passkeys)."""

from __future__ import annotations

from rba_idp.db.models import WebAuthnCredential
from rba_idp.db.session import make_engine, make_session_factory
from rba_idp.init import initialise
from rba_idp.passkeys import export_passkeys, import_passkeys
from tests.helpers import test_settings as make_settings


def _fresh():
    settings = make_settings()
    engine = make_engine("sqlite+pysqlite://", memory=True)
    initialise(settings, engine)
    return make_session_factory(engine)


def test_export_then_import_into_a_fresh_database():
    old = _fresh()
    with old() as session:
        session.add(WebAuthnCredential(credential_id="cred-1", user_id="usr_rb_martin", public_key=b"\x01pk", sign_count=7))
        session.add(WebAuthnCredential(credential_id="cred-2", user_id="usr_rs_juan", public_key=b"\x02pk", sign_count=0))
        session.commit()
    dump = export_passkeys(old)
    assert {d["credential_id"] for d in dump} == {"cred-1", "cred-2"}

    new = _fresh()  # what aws-up seeds: same users, no passkeys
    assert import_passkeys(new, dump + [{**dump[0], "credential_id": "gone", "user_id": "usr_deleted"}]) == {
        "added": 2, "updated": 0, "skipped": 1}
    with new() as session:
        row = session.get(WebAuthnCredential, "cred-1")
        assert (row.user_id, row.public_key, row.sign_count) == ("usr_rb_martin", b"\x01pk", 7)

    # Importing twice is harmless; a higher counter wins.
    assert import_passkeys(new, [{**dump[0], "sign_count": 9}]) == {"added": 0, "updated": 1, "skipped": 0}
