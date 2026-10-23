from triage.errors import ApiError
from tests.helpers import AppTestCase


class AuthTests(AppTestCase):
    def test_login_and_authenticate(self):
        user, pw = self.make_user()
        access, refresh, info = self.app.auth.login("alice", pw, "1.2.3.4")
        self.assertEqual(info["username"], "alice")
        principal = self.app.auth.authenticate(access)
        self.assertEqual((principal.username, principal.role), ("alice", "triager"))

    def test_bad_password_and_unknown_user_look_the_same(self):
        self.make_user()
        for username, pw in (("alice", "wrong password!!"), ("nobody", "whatever password")):
            with self.assertRaises(ApiError) as ctx:
                self.app.auth.login(username, pw, "1.2.3.4")
            self.assertEqual((ctx.exception.status, ctx.exception.message), (401, "invalid username or password"))

    def test_refresh_rotates(self):
        _, pw = self.make_user()
        _, r1, _ = self.app.auth.login("alice", pw, "ip")
        _, r2, _ = self.app.auth.refresh(r1, "ip")
        self.assertNotEqual(r1, r2)
        self.app.auth.refresh(r2, "ip")  # the new one works

    def test_refresh_reuse_revokes_the_whole_family(self):
        _, pw = self.make_user()
        _, r1, _ = self.app.auth.login("alice", pw, "ip")
        _, r2, _ = self.app.auth.refresh(r1, "ip")  # legitimate client rotates
        with self.assertRaises(ApiError):
            self.app.auth.refresh(r1, "attacker")  # stolen old token replayed
        with self.assertRaises(ApiError):
            self.app.auth.refresh(r2, "ip")  # ...so the legitimate token is dead too
        actions = [e["action"] for e in self.app.audit.list()]
        self.assertIn("auth.refresh_reuse_detected", actions)

    def test_logout_revokes(self):
        _, pw = self.make_user()
        _, r1, _ = self.app.auth.login("alice", pw, "ip")
        self.app.auth.logout(r1, "user:alice")
        with self.assertRaises(ApiError):
            self.app.auth.refresh(r1, "ip")

    def test_deactivation_takes_effect_immediately(self):
        admin, admin_pw = self.make_user("root", "admin")
        user, pw = self.make_user()
        access, refresh, _ = self.app.auth.login("alice", pw, "ip")
        admin_principal = self.app.auth.authenticate(self.app.auth.login("root", admin_pw, "ip")[0])
        self.app.users.update(user["id"], admin_principal, active=False)
        with self.assertRaises(ApiError):
            self.app.auth.authenticate(access)  # still unexpired, but rejected
        with self.assertRaises(ApiError):
            self.app.auth.refresh(refresh, "ip")

    def test_refresh_token_cannot_be_used_as_access_token(self):
        _, pw = self.make_user()
        _, refresh, _ = self.app.auth.login("alice", pw, "ip")
        with self.assertRaises(ApiError):
            self.app.auth.authenticate(refresh)

    def test_admin_cannot_lock_themselves_out(self):
        admin, pw = self.make_user("root", "admin")
        principal = self.app.auth.authenticate(self.app.auth.login("root", pw, "ip")[0])
        with self.assertRaises(ApiError):
            self.app.users.update(admin["id"], principal, active=False)

    def test_user_validation(self):
        with self.assertRaises(ApiError):
            self.app.users.create("x", "long enough password", "triager", "test")
        with self.assertRaises(ApiError):
            self.app.users.create("bob", "short", "triager", "test")
        with self.assertRaises(ApiError):
            self.app.users.create("bob", "long enough password", "superuser", "test")
        self.make_user("bob")
        with self.assertRaises(ApiError) as ctx:
            self.make_user("BOB")  # usernames are case-insensitive
        self.assertEqual(ctx.exception.status, 409)
