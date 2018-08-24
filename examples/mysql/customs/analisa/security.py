import flask
from flask import redirect, g, flash, request, Markup, current_app
from xmltodict import parse
try:
    from urllib import urlopen
    from urllib import quote
    from urllib import urlencode
    from urlparse import urljoin
except ImportError:
    from urllib.request import urlopen
    from urllib.parse import quote
    from urllib.parse import urljoin
    from urllib.parse import urlencode

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user


# --------------------------------------------------------------------------------------

SIMPLE_LOGIN_PAGE_CONTENT = """
    <html>
        <body>
        <a href="http://localhost:8088/login?username=admin&redirect=/superset/welcome">This link will auto login as admin</a>
        <body>
    <html>
"""

# Based on https://medium.com/@sairamkrish/apache-superset-custom-authentication-and-integrate-with-other-micro-services-8217956273c1
class SimpleCustomAuthDBView(AuthDBView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):

        redirect_url = self.appbuilder.get_url_for_index
        if request.args.get('redirect') is not None:
            redirect_url = request.args.get('redirect')
        
        print(redirect_url)
        print(request.args.get('username'))

        if request.args.get('username') is not None:
            user = self.appbuilder.sm.find_user(username=request.args.get('username'))
            if user is not None:
                login_user(user, remember=False)
                return redirect(redirect_url)
            else:
                return "Unknow user '{}'".format(request.args.get('username'))

        elif g.user is not None and g.user.is_authenticated():
            return redirect(redirect_url)
        else:
            return SIMPLE_LOGIN_PAGE_CONTENT

class SimpleCustomSecurityManager(SupersetSecurityManager):
    authdbview = SimpleCustomAuthDBView
    def __init__(self, appbuilder):
        super(SimpleCustomSecurityManager, self).__init__(appbuilder)

# --------------------------------------------------------------------------------------


# Based on https://medium.com/@sairamkrish/apache-superset-custom-authentication-and-integrate-with-other-micro-services-8217956273c1
class CasCustomAuthDBView(AuthDBView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        if 'CAS_USERNAME' not in flask.session:
            flask.session['CAS_AFTER_LOGIN_SESSION_URL'] = flask.request.path
            return cas_login()
        else:
            username = flask.session.get(current_app.config['CAS_USERNAME_SESSION_KEY'], None)
            attributes = flask.session.get(current_app.config['CAS_ATTRIBUTES_SESSION_KEY'], None)
            print(username)
            print(attributes)
            
            user = self.appbuilder.sm.find_user(username=username)
            if user:
                login_user(user, remember=False)
            else:
                self.appbuilder.sm.add_user(username=username,
                                               email="{}@ufg.br".format(username),
                                               first_name=username,
                                               last_name=username,
                                               role=self.appbuilder.sm.find_role(
                                                       self.appbuilder.sm.auth_user_registration_role))
                user = self.appbuilder.sm.find_user(username=username)
                login_user(user, remember=False)
            redirect_url = self.appbuilder.get_url_for_index
            return flask.redirect(redirect_url)

    @expose('/logout/')
    def logout(self):
        logout_user()        
        return cas_logout()     

class CasCustomSecurityManager(SupersetSecurityManager):
    authdbview = CasCustomAuthDBView
    def __init__(self, appbuilder):
        super(CasCustomSecurityManager, self).__init__(appbuilder)

def cas_login():
    """
    This route has two purposes. First, it is used by the user
    to login. Second, it is used by the CAS to respond with the
    `ticket` after the user logs in successfully.
    When the user accesses this url, they are redirected to the CAS
    to login. If the login was successful, the CAS will respond to this
    route with the ticket in the url. The ticket is then validated.
    If validation was successful the logged in username is saved in
    the user's session under the key `CAS_USERNAME_SESSION_KEY` and
    the user's attributes are saved under the key
    'CAS_USERNAME_ATTRIBUTE_KEY'
    """

    cas_token_session_key = current_app.config['CAS_TOKEN_SESSION_KEY']

    redirect_url = create_cas_login_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_LOGIN_ROUTE'],
        flask.url_for('.login', _external=True))

    if 'ticket' in flask.request.args:
        flask.session[cas_token_session_key] = flask.request.args['ticket']

    if cas_token_session_key in flask.session:

        if cas_validate(flask.session[cas_token_session_key]):
            if 'CAS_AFTER_LOGIN_SESSION_URL' in flask.session:
                redirect_url = flask.session.pop('CAS_AFTER_LOGIN_SESSION_URL')
            else:
                redirect_url = flask.url_for(
                    current_app.config['CAS_AFTER_LOGIN'])
        else:
            del flask.session[cas_token_session_key]

    current_app.logger.debug('Redirecting to: {0}'.format(redirect_url))

    return flask.redirect(redirect_url)


def cas_logout():
    """
    When the user accesses this route they are logged out.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
    cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']

    if cas_username_session_key in flask.session:
        del flask.session[cas_username_session_key]

    if cas_attributes_session_key in flask.session:
        del flask.session[cas_attributes_session_key]

    if(current_app.config['CAS_AFTER_LOGOUT'] != None):
        redirect_url = create_cas_logout_url(
            current_app.config['CAS_SERVER'],
            current_app.config['CAS_LOGOUT_ROUTE'],
            current_app.config['CAS_AFTER_LOGOUT'])
    else:
        redirect_url = create_cas_logout_url(
            current_app.config['CAS_SERVER'],
            current_app.config['CAS_LOGOUT_ROUTE'])

    current_app.logger.debug('Redirecting to: {0}'.format(redirect_url))
    return flask.redirect(redirect_url)


def cas_validate(ticket):
    """
    Will attempt to validate the ticket. If validation fails, then False
    is returned. If validation is successful, then True is returned
    and the validated username is saved in the session under the
    key `CAS_USERNAME_SESSION_KEY` while tha validated attributes dictionary
    is saved under the key 'CAS_ATTRIBUTES_SESSION_KEY'.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
    cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']

    current_app.logger.debug("validating token {0}".format(ticket))

    cas_validate_url = create_cas_validate_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_VALIDATE_ROUTE'],
        flask.url_for('.login', _external=True),
        ticket)

    current_app.logger.debug("Making GET request to {0}".format(
        cas_validate_url))

    xml_from_dict = {}
    isValid = False

    try:        
        xmldump = urlopen(cas_validate_url).read().strip().decode('utf8', 'ignore')
        xml_from_dict = parse(xmldump)
        isValid = True if "cas:authenticationSuccess" in xml_from_dict["cas:serviceResponse"] else False
    except ValueError:
        current_app.logger.error("CAS returned unexpected result")

    if isValid:
        current_app.logger.debug("valid")
        xml_from_dict = xml_from_dict["cas:serviceResponse"]["cas:authenticationSuccess"]
        username = xml_from_dict["cas:user"]
        attributes = xml_from_dict.get("cas:attributes", {})

        if "cas:memberOf" in attributes:
            attributes["cas:memberOf"] = attributes["cas:memberOf"].lstrip('[').rstrip(']').split(',')
            for group_number in range(0, len(attributes['cas:memberOf'])):
                attributes['cas:memberOf'][group_number] = attributes['cas:memberOf'][group_number].lstrip(' ').rstrip(' ')

        flask.session[cas_username_session_key] = username
        flask.session[cas_attributes_session_key] = attributes
    else:
        current_app.logger.debug("invalid")

    return isValid

def create_url(base, path=None, *query):
    """ Create a url.
    Creates a url by combining base, path, and the query's list of
    key/value pairs. Escaping is handled automatically. Any
    key/value pair with a value that is None is ignored.
    Keyword arguments:
    base -- The left most part of the url (ex. http://localhost:5000).
    path -- The path after the base (ex. /foo/bar).
    query -- A list of key value pairs (ex. [('key', 'value')]).
    Example usage:
    >>> create_url(
    ...     'http://localhost:5000',
    ...     'foo/bar',
    ...     ('key1', 'value'),
    ...     ('key2', None),     # Will not include None
    ...     ('url', 'http://example.com'),
    ... )
    'http://localhost:5000/foo/bar?key1=value&url=http%3A%2F%2Fexample.com'
    """
    url = base
    # Add the path to the url if it's not None.
    if path is not None:
        url = urljoin(url, quote(path))
    # Remove key/value pairs with None values.
    query = filter(lambda pair: pair[1] is not None, query)
    # Add the query string to the url
    url = urljoin(url, '?{0}'.format(urlencode(list(query))))
    return url


def create_cas_login_url(cas_url, cas_route, service, renew=None, gateway=None):
    """ Create a CAS login URL .
    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route -- The route where the CAS lives on server (ex. /cas)
    service -- (ex.  http://localhost:5000/login)
    renew -- "true" or "false"
    gateway -- "true" or "false"
    Example usage:
    >>> create_cas_login_url(
    ...     'http://sso.pdx.edu',
    ...     '/cas',
    ...     'http://localhost:5000',
    ... )
    'http://sso.pdx.edu/cas?service=http%3A%2F%2Flocalhost%3A5000'
    """
    return create_url(
        cas_url,
        cas_route,
        ('service', service),
        ('renew', renew),
        ('gateway', gateway),
    )


def create_cas_logout_url(cas_url, cas_route, service=None):
    """ Create a CAS logout URL.
    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route -- The route where the CAS lives on server (ex. /cas/logout)
    url -- (ex.  http://localhost:5000/login)
    Example usage:
    >>> create_cas_logout_url(
    ...     'http://sso.pdx.edu',
    ...     '/cas/logout',
    ...     'http://localhost:5000',
    ... )
    'http://sso.pdx.edu/cas/logout?service=http%3A%2F%2Flocalhost%3A5000'
    """
    return create_url(
        cas_url,
        cas_route,
        ('service', service),
    )


def create_cas_validate_url(cas_url, cas_route, service, ticket,
                            renew=None):
    """ Create a CAS validate URL.
    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route -- The route where the CAS lives on server (ex. /cas/serviceValidate)
    service -- (ex.  http://localhost:5000/login)
    ticket -- (ex. 'ST-58274-x839euFek492ou832Eena7ee-cas')
    renew -- "true" or "false"
    Example usage:
    >>> create_cas_validate_url(
    ...     'http://sso.pdx.edu',
    ...     '/cas/serviceValidate',
    ...     'http://localhost:5000/login',
    ...     'ST-58274-x839euFek492ou832Eena7ee-cas'
    ... )
    'http://sso.pdx.edu/cas/serviceValidate?service=http%3A%2F%2Flocalhost%3A5000%2Flogin&ticket=ST-58274-x839euFek492ou832Eena7ee-cas'
    """
    return create_url(
        cas_url,
        cas_route,
        ('service', service),
        ('ticket', ticket),
        ('renew', renew),
    )