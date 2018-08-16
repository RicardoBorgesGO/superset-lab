from flask import Blueprint
from flask import g

analisa = Blueprint('analisa', __name__, template_folder='templates')

@analisa.route('/analisa/', defaults={'page': 'index'})
@analisa.route('/analisa/<page>')
def show(page):    
    return page
