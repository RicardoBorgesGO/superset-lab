from flask import redirect, g, flash, request, Markup
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user

# Based on https://medium.com/@sairamkrish/apache-superset-custom-authentication-and-integrate-with-other-micro-services-8217956273c1
class CustomAuthDBView(AuthDBView):
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
            return """
                <html>
                  <body>
                    <a href="http://localhost:8088/login?username=admin&redirect=/superset/welcome">This link will auto login as admin</a>
                  <body>
                <html>
            """

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
