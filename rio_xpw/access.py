# coding:utf-8

from dataclasses import dataclass
from typing import Any
from typing import Generic
from typing import Optional
from typing import Type
from typing import TypeVar

from rio import App
from rio import Session
from rio import UserSettings
from xpw import Account
from xpw import Profile
from xpw import Secret
from xpw import SessionID
from xpw import SessionUser


@dataclass
class EndUser(UserSettings):
    """Model for data stored client-side for each user.

    Any classes inheriting from `rio.UserSettings` will be automatically
    stored on the client's device when attached to the session. Thus, we
    can check if the user has a valid auth token stored.

    This prevents users from having to log-in again each time the page is
    accessed.
    """

    session_id: str
    secret_key: str

    @classmethod
    def nobody(cls, **kwargs: Any):
        kwargs["session_id"] = ""
        kwargs["secret_key"] = ""
        return cls(**kwargs)

    @classmethod
    def guest(cls):
        raise NotImplementedError


User = TypeVar("User", bound=EndUser)


class AccessControl(Generic[User]):

    def __init__(self, users: Account, dummy: User = EndUser.nobody()):
        if not issubclass(proto := type(dummy), EndUser):
            raise TypeError(f"{proto} is not EndUser or subclass.")

        self.__proto: Type[User] = proto
        self.__users: Account = users
        self.__dummy: User = dummy

    @property
    def prototype(self) -> Type[User]:
        return self.__proto

    @property
    def users(self) -> Account:
        return self.__users

    def activate(self, username: str, password: str, session_id: str, secret_key: Optional[str] = None) -> Optional[SessionUser]:  # noqa:E501
        return self.users.login(username, password, session_id, secret_key or Secret.generate().key)  # noqa:E501

    def deactivate(self, user: User) -> bool:
        return self.users.logout(session_id=user.session_id, secret_key=user.secret_key)  # noqa:E501

    def identify(self, user: User) -> Optional[Profile]:
        return self.users.fetch(session_id=user.session_id, secret_key=user.secret_key)  # noqa:E501

    def validate(self, session: Session) -> bool:
        try:
            if profile := self.identify(user=session[self.prototype]):
                session.attach(profile)
                return True
        except KeyError:
            pass

        return False

    async def on_app_start(self, app: App) -> None:
        app.default_attachments.append(self.__dummy)
        app.default_attachments.append(self)

    async def on_session_start(self, session: Session) -> None:
        if not (user := session[self.prototype]).session_id:
            user.session_id = SessionID.generate()
            session.attach(user)

    @classmethod
    def from_file(cls, config: Optional[str] = None, dummy: User = EndUser.nobody()) -> "AccessControl[User]":  # noqa:E501
        return cls(users=Account.from_file(config=config), dummy=dummy)
