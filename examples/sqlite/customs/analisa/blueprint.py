from flask import Blueprint, render_template

saiku = Blueprint('saiku', __name__, template_folder='templates')

@saiku.route('/saiku/', defaults={'page': 'index'})
@saiku.route('/saiku/<page>')
def show(page):    
    from superset import appbuilder
    return render_template('saiku/saiku.html', appbuilder=appbuilder)
