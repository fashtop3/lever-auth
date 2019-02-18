import datetime
import jwt
from flask import current_app


def jwt_encode_auth_token(data, private_key):
    """Generates the auth token"""
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(
                days=current_app.config.get('JWT_TOKEN_EXPIRATION_DAYS'),
                seconds=current_app.config.get('JWT_TOKEN_EXPIRATION_SECONDS')
            ),
            'iss': current_app.config.get('JWT_TOKEN_ISSUER'),
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
            issuer=current_app.config.get('JWT_TOKEN_ISSUER'),
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
