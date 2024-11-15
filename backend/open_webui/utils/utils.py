import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional, Union

import jwt
from open_webui.apps.webui.models.users import Users
from open_webui.constants import ERROR_MESSAGES
from open_webui.env import WEBUI_SECRET_KEY
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

logging.getLogger("passlib").setLevel(logging.ERROR)

#Constants
SESSION_SECRET = WEBUI_SECRET_KEY # The secret key for JWT token encoding/decoding
ALGORITHM = "HS256" # Algorithm used for encoding/decoding JWT tokens

##############
# Auth Utils
##############

# Initialize the HTTP bearer security scheme to handle token-based authentication
bearer_security = HTTPBearer(auto_error=False)
# Initilizes password for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return (
        #Verifies if the provided plain password matches the hashed password
        pwd_context.verify(plain_password, hashed_password) if hashed_password else None
    )


def get_password_hash(password):
    #Returns the hashed version of the given password using bcrypt
    return pwd_context.hash(password)

#Creates Token with the given data and optional expiration time
def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
        payload.update({"exp": expire})

    encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

#Decodes token and returns the payload or None if the token is invalid
def decode_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, SESSION_SECRET, algorithms=[ALGORITHM])
        return decoded
    except Exception:
        return None

#Extracts the token from the 'Authorization' header
def extract_token_from_auth_header(auth_header: str):
    return auth_header[len("Bearer ") :]

#Generates and returns a new API key
def create_api_key():
    key = str(uuid.uuid4()).replace("-", "")
    return f"sk-{key}"


def get_http_authorization_cred(auth_header: str):
    try:
        scheme, credentials = auth_header.split(" ")
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
    except Exception:
        raise ValueError(ERROR_MESSAGES.INVALID_TOKEN)


####################
'''Retrieves the currently authenticated user. '''
'''Authenticates using either a token or an API key.'''
####################
def get_current_user(
    request: Request,
    auth_token: HTTPAuthorizationCredentials = Depends(bearer_security),
):
    token = None

    # Check for the token in the 'Authorization' header first
    if auth_token is not None:
        token = auth_token.credentials

    # If no token in the header, check for it in the cookies
    if token is None and "token" in request.cookies:
        token = request.cookies.get("token")

    # If no token found, send 403 error
    if token is None:
        raise HTTPException(status_code=403, detail="Not authenticated")

    # If token starts with 'sk-', treat it as an API key
    # auth by api key
    if token.startswith("sk-"):
        return get_current_user_by_api_key(token)

    # auth by jwt token
    #Otherwise, decode the token as a JWT
    data = decode_token(token)
    if data is not None and "id" in data:
        # If the decoded token contains a valid user ID, fetch the user
        user = Users.get_user_by_id(data["id"])
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.INVALID_TOKEN,
            )
        else:
            Users.update_user_last_active_by_id(user.id)
        return user
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

#Fetches the user based on the provided API key
def get_current_user_by_api_key(api_key: str):
    user = Users.get_user_by_api_key(api_key)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )
    else:
        Users.update_user_last_active_by_id(user.id)

    return user

####################
'''Ensures the authenticated user has a role of 'user' or 'admin'''
####################
def get_verified_user(user=Depends(get_current_user)):
    if user.role not in {"user", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user

####################
'''Ensures the authenticated user has an 'admin' role.
We can modify to only allow admin these prevleges of adding new roles assigning
'''
####################
def get_admin_user(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user

