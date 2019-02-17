import datetime
import jwt
from functools import wraps
from flask import request, jsonify


# from jwt import InvalidIssuerError


class LeverJWTConfig:
    JWT_TOKEN_EXPIRATION_DAYS = 0
    JWT_TOKEN_EXPIRATION_SECONDS = 0


def jwt_encode_auth_token(data, private_key):
    """
    Generates the auth token using RS256
    :param data:
    :return:
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(
                days=LeverJWTConfig.JWT_TOKEN_EXPIRATION_DAYS,
                seconds=LeverJWTConfig.JWT_TOKEN_EXPIRATION_SECONDS
            ),
            'iss': 'urn:lever',
            'iat': datetime.datetime.utcnow(),
            'sub': data
        }
        encoded = jwt.encode(payload, private_key, algorithm='RS256')
        return encoded
    except Exception as e:
        return e


def jwt_decode_auth_token(auth_token, public_key):
    """
    Decodes the auth token - :param auth_token: - :return: integer|string
    """
    try:
        payload = jwt.decode(
            auth_token,
            public_key,
            issuer='urn:lever',
            algorithms='RS256'
        )
        return payload['sub']
    except jwt.InvalidIssuerError:
        return 'Invalid issuer. Please log in again.'
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
    except Exception as e:
        return 'Invalid token. Please log in again.'


def authenticate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response_object = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify(response_object), 403
        auth_token = auth_header.split(" ")[1]
        resp = jwt_decode_auth_token(auth_token)
        if isinstance(resp, str):
            response_object['message'] = resp
            return jsonify(response_object), 401
        kwargs.update(dict(resp=resp))
        return f(*args, **kwargs)

    return decorated_function
