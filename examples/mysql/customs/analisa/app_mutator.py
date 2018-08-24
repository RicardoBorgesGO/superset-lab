def mutator(app):    
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
      href='/saiku',
      icon='fa-refresh',
      category='',
      category_icon='fa-database')

    print("Created 'Saiku' menu.")
