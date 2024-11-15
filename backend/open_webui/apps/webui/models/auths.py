import logging
import uuid
from typing import Optional

from open_webui.apps.webui.internal.db import Base, get_db
from open_webui.apps.webui.models.users import UserModel, Users
from open_webui.env import SRC_LOG_LEVELS
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, String, Text
from open_webui.utils.utils import verify_password

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MODELS"])

####################
# DB MODEL

# Manage user authentication and authorization within a system. Provides mechanisms 
# for users to sign up, log in, and update their account information while also handling 
# basic user roles and permissions.
####################

#User authentication details
class Auth(Base):
    __tablename__ = "auth"

    id = Column(String, primary_key=True)
    email = Column(String)
    password = Column(Text)
    active = Column(Boolean)


class AuthModel(BaseModel):
    id: str
    email: str
    password: str
    active: bool = True


####################
# Forms
####################


class Token(BaseModel):
    token: str
    token_type: str


class ApiKey(BaseModel):
    api_key: Optional[str] = None

# provides user information
class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    profile_image_url: str

# token and user infomation
class SigninResponse(Token, UserResponse):
    pass

#form given to sign in with email and password
class SigninForm(BaseModel):
    email: str
    password: str

# updates image uploaded
class ProfileImageUrlForm(BaseModel):
    profile_image_url: str

# updates user name and profile pic
class UpdateProfileForm(BaseModel):
    profile_image_url: str
    name: str

# updates user password
class UpdatePasswordForm(BaseModel):
    password: str
    new_password: str

# for used to register new users --> name, email, password and photo if wanted
class SignupForm(BaseModel):
    name: str
    email: str
    password: str
    profile_image_url: Optional[str] = "/user.png"

# Form to add new users, along with roles to be assigned but is pending as default
class AddUserForm(SignupForm):
    role: Optional[str] = "pending"

# manages user authentication like making account, signing in and password management
class AuthsTable:
    #Method that inserts new users to the database with email and password
    def insert_new_auth(
        self,
        email: str,
        password: str,
        name: str,
        profile_image_url: str = "/user.png",
        role: str = "pending",
        oauth_sub: Optional[str] = None,
    ) -> Optional[UserModel]:
        with get_db() as db:
            log.info("insert_new_auth")

            #generates a unique ID for new users
            id = str(uuid.uuid4())

            # creates a table with provided details
            auth = AuthModel(
                **{"id": id, "email": email, "password": password, "active": True}
            )
            result = Auth(**auth.model_dump())
            db.add(result)

            # Inserts new user to the Users table with specified role
            user = Users.insert_new_user(
                id, name, email, profile_image_url, role, oauth_sub
            )

            db.commit()
            db.refresh(result)

            if result and user:
                return user
            else:
                return None

    # Mehod that authenticates a user with email and password
    def authenticate_user(self, email: str, password: str) -> Optional[UserModel]:
        log.info(f"authenticate_user: {email}")
        try:
            with get_db() as db:
                auth = db.query(Auth).filter_by(email=email, active=True).first()
                if auth:
                    if verify_password(password, auth.password):
                        user = Users.get_user_by_id(auth.id)
                        return user
                    else:
                        return None
                else:
                    return None
        except Exception:
            return None

    # Method used to authenticate a user with an API Key
    def authenticate_user_by_api_key(self, api_key: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_api_key: {api_key}")
        # if no api_key, return None
        if not api_key:
            return None

        try:
            user = Users.get_user_by_api_key(api_key)
            return user if user else None
        except Exception:
            return False

    #Method that authenticates a user using a trusted header
    def authenticate_user_by_trusted_header(self, email: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_trusted_header: {email}")
        try:
            with get_db() as db:
                auth = db.query(Auth).filter_by(email=email, active=True).first()
                if auth:
                    user = Users.get_user_by_id(auth.id)
                    return user
        except Exception:
            return None

    # Method that updates a users password by ID
    def update_user_password_by_id(self, id: str, new_password: str) -> bool:
        try:
            with get_db() as db:
                result = (
                    db.query(Auth).filter_by(id=id).update({"password": new_password})
                )
                db.commit()
                return True if result == 1 else False
        except Exception:
            return False

    # Method that updates a users email by ID
    def update_email_by_id(self, id: str, email: str) -> bool:
        try:
            with get_db() as db:
                result = db.query(Auth).filter_by(id=id).update({"email": email})
                db.commit()
                return True if result == 1 else False
        except Exception:
            return False

    # Method that deletes users and info by ID 
    def delete_auth_by_id(self, id: str) -> bool:
        try:
            with get_db() as db:
                # Delete User
                result = Users.delete_user_by_id(id)

                if result:
                    db.query(Auth).filter_by(id=id).delete()
                    db.commit()

                    return True
                else:
                    return False
        except Exception:
            return False

#Creates an instance of AuthsTable
Auths = AuthsTable()
