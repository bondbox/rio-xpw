# coding:utf-8

from asyncio import run
from dataclasses import dataclass
from pathlib import Path
from unittest import TestCase
from unittest import main

from rio import App
from rio import Session
from rio import UserSettings
from rio.app_server.testing_server import TestingServer
from xpw import Profile
from xpw import Secret
from xpw import SessionID
from xpw import SessionUser

from rio_xpw.access import AccessControl
from rio_xpw.access import EndUser


@dataclass
class TestUser(EndUser):

    username: str

    @classmethod
    def guest(cls):
        return cls.nobody(username="nobody")


class TestAccessControl(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.path: str = str(Path(__file__).parent.joinpath("xpwauth"))
        cls.guest: TestUser = TestUser.guest()
        cls.username: str = "demo"
        cls.password: str = "unit"

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.session_id: str = SessionID.generate()
        self.secret_key: str = Secret.generate().key
        self.access_control: AccessControl[TestUser] = AccessControl[TestUser].from_file(self.path, self.guest)  # noqa:E501
        user = self.access_control.activate(self.username, self.password, self.session_id, self.secret_key)  # noqa:E501
        self.assertIsInstance(user, SessionUser)
        assert isinstance(user, SessionUser)
        self.user: SessionUser = user

    def tearDown(self):
        pass

    def test_init(self):
        self.assertRaises(TypeError, AccessControl.from_file, config=self.path, dummy=UserSettings())  # noqa:E501

    def test_deactivate(self):
        user = TestUser(session_id=self.user.session_id, secret_key=self.user.secret_key, username=self.username)  # noqa:E501
        self.assertIs(self.access_control.activate(self.username, self.password, self.session_id, self.secret_key), self.user)  # noqa:E501
        self.assertIsInstance(self.access_control.identify(user), Profile)
        self.assertTrue(self.access_control.deactivate(user))
        self.assertIsNone(self.access_control.identify(user))
        self.assertTrue(self.access_control.deactivate(user))

    def test_restrict(self):
        self.assertIs(self.access_control.activate(self.username, self.password, self.session_id, self.secret_key), self.user)  # noqa:E501
        user = TestUser(session_id=self.user.session_id, secret_key=self.user.secret_key, username=self.username)  # noqa:E501
        session: Session = TestingServer(app=App()).create_dummy_session()
        self.assertFalse(self.access_control.validate(session=session))
        session._attachments._add(value=user, synchronize=False)
        self.assertTrue(self.access_control.validate(session=session))

    def test_on_app_start(self):
        self.assertIsNone(run(self.access_control.on_app_start(app=App())))

    def test_on_session_start(self):
        session: Session = TestingServer(app=App()).create_dummy_session()
        session._attachments._add(value=self.guest, synchronize=False)
        self.assertIsNone(run(self.access_control.on_session_start(session=session)))  # noqa:E501


if __name__ == "__main__":
    main()
