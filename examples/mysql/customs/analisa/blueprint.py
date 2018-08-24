from flask import Blueprint, render_template, g
import requests
import time

URL_SAIKU_SESSION = 'https://analisa.dados.ufg.br/saiku/rest/saiku/session'

saiku = Blueprint('saiku', __name__, template_folder='templates')
print(saiku)

@saiku.route('/saiku-page/')
def show_saiku_page():    
    from superset import appbuilder
    return render_template('saiku/saiku.html', appbuilder=appbuilder)

@saiku.route('/saiku-page/session/')
def get_saiku_session():        
    # If superset has an user in session
    if g.user is not None and hasattr(g.user, 'username'):
        # Perform first request to create a session on saiku backend and to receive the cookie
        r1 = requests.post(URL_SAIKU_SESSION, 
                           data = {'username': g.user.username, 
                                   'password': 'secret', 
                                   'isadmin': 'true', 
                                   'language': 'pt'}, 
                           verify=False)

        timestamp = int(time.time())
        # Perform second request to receive from saiku backend the json with info session.
        r2 = requests.get((URL_SAIKU_SESSION + '?_={}').format(timestamp), 
                          cookies=r1.cookies, 
                          verify=False)
        
        # Return json with info session
        return r2.text
    else:
        # Return a void json
        return "{}"