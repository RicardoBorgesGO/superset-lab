import os

MAPBOX_API_KEY = os.getenv('MAPBOX_API_KEY', '')
MAPBOX_API_KEY = 'pk.eyJ1IjoiZGFubnllbGNmIiwiYSI6ImNqa21zMXFjYzAxYnczcG55ejlmc3M2YW0ifQ.1MuERshcsppKphhii357hg'
CACHE_CONFIG = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'superset_',
    'CACHE_REDIS_HOST': 'redis',
    'CACHE_REDIS_PORT': 6379,
    'CACHE_REDIS_DB': 1,
    'CACHE_REDIS_URL': 'redis://redis:6379/1'}
SQLALCHEMY_DATABASE_URI = 'sqlite:////var/lib/superset/superset.db'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'thisISaSECRET_1234'
PUBLIC_ROLE_LIKE_GAMMA = True

#-------------------------------------------------------------------------------

from flask import Blueprint
from flask import g

test = Blueprint('test', __name__, template_folder='templates')

@test.route('/', defaults={'page': 'index'})
@test.route('/<page>')
def show(page):    
    return page    

BLUEPRINTS = [test]

#-------------------------------------------------------------------------------

from flask import redirect, g, flash, request, Markup
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user

# Based on https://medium.com/@sairamkrish/apache-superset-custom-authentication-and-integrate-with-other-micro-services-8217956273c1
class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        redirect_url = self.appbuilder.get_url_for_index
        if request.args.get('redirect') is not None:
            redirect_url = request.args.get('redirect')
        
        print(redirect_url)
        print(request.args.get('username'))

        if request.args.get('username') is not None:
            user = self.appbuilder.sm.find_user(username=request.args.get('username'))
            login_user(user, remember=False)
            return redirect(redirect_url)
        elif g.user is not None and g.user.is_authenticated():
            return redirect(redirect_url)
        else:
            message = Markup('The following link will auto login as admin: <a href="http://localhost:8088/login?username=admin&redirect=/superset/welcome">link</a>')
            flash(message, 'warning')
            return super(CustomAuthDBView,self).login()

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)

CUSTOM_SECURITY_MANAGER = CustomSecurityManager

#-------------------------------------------------------------------------------

def test(app):
    from flask_appbuilder.baseviews import expose_api
    from flask_appbuilder.security.decorators import has_access_api
    from flask_babel import gettext as __
    from superset import appbuilder
    from superset.views.core import BaseSupersetView

    class TestView(BaseSupersetView):
        @expose_api(name='api', url='/api/refresh', methods=['GET'])
        @expose_api(name='api', url='/api/refresh/<project_id>', methods=['GET'])
        @has_access_api
        def refresh(self, project_id=None):
            pass

    appbuilder.add_view(
      TestView,
      'Test',
      label=__('Test'),
      href='/test',
      icon='fa-refresh',
      category='',
      category_icon='fa-database')

    print("Created 'Test' menu.")

FLASK_APP_MUTATOR = test

