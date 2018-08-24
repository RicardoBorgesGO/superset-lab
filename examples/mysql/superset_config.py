import os

MAPBOX_API_KEY = os.getenv('MAPBOX_API_KEY', '')
CACHE_CONFIG = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'superset_',
    'CACHE_REDIS_HOST': 'redis',
    'CACHE_REDIS_PORT': 6379,
    'CACHE_REDIS_DB': 1,
    'CACHE_REDIS_URL': 'redis://redis:6379/1'}
SQLALCHEMY_DATABASE_URI = 'mysql://superset:superset@mysql:3306/superset'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'thisISaSECRET_1234'
PUBLIC_ROLE_LIKE_GAMMA = True

#-------------------------------------------------------------------------------

print("Loading ADDITIONAL_MIDDLEWARE...")
from customs.analisa.middleware import ReverseProxied
ADDITIONAL_MIDDLEWARE = [ReverseProxied, ]

#-------------------------------------------------------------------------------

print("Loading BLUEPRINTS...")
from customs.analisa.blueprint import saiku
BLUEPRINTS = [saiku]

#-------------------------------------------------------------------------------

print("Loading CUSTOM_SECURITY_MANAGER...")
from customs.analisa.security import CasCustomSecurityManager
CUSTOM_SECURITY_MANAGER = CasCustomSecurityManager

#-------------------------------------------------------------------------------

print("Loading FLASK_APP_MUTATOR...")
from customs.analisa.app_mutator import mutator
FLASK_APP_MUTATOR = mutator

