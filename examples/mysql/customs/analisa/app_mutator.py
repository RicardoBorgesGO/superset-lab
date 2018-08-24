def mutator(app):    
    config_cas(app)
    create_menu_saiku(app)

def config_cas(app):
    print("Config CAS...")
    # Configuration defaults
    app.config.setdefault('CAS_TOKEN_SESSION_KEY', '_CAS_TOKEN')
    app.config.setdefault('CAS_USERNAME_SESSION_KEY', 'CAS_USERNAME')
    app.config.setdefault('CAS_ATTRIBUTES_SESSION_KEY', 'CAS_ATTRIBUTES')
    app.config.setdefault('CAS_LOGIN_ROUTE', '/cas')
    app.config.setdefault('CAS_LOGOUT_ROUTE', '/cas/logout')
    app.config.setdefault('CAS_VALIDATE_ROUTE', '/cas/serviceValidate')
    # Requires CAS 2.0
    app.config.setdefault('CAS_AFTER_LOGOUT', 'https://analisa.dados.ufg.br/analytics')
    #
    app.config['CAS_SERVER'] = 'https://cas-homologacao.sistemas.ufg.br'

def create_menu_saiku(app):
    print("Creating 'Saiku' menu.")
    from flask_babel import gettext as __
    from superset import appbuilder
    from superset.views.core import BaseSupersetView

    class SaikuView(BaseSupersetView):       
        def refresh(self):
            pass

    appbuilder.add_view(
      SaikuView,
      'Saiku',
      label=__('Saiku'),
      href='/saiku-page',
      icon='fa-refresh',
      category='',
      category_icon='fa-database')