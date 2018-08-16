def mutator(app):
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
