"""Provides interface to database.

Version 1 schema:
    * cur_wordpres_ver (1 row)
        * version (TEXT PRIMARY KEY)
    * cur_plugins_ver
        * plugin_url (TEXT PRIMARY KEY)
        * version (TEXT)
"""

#wordpress-notifier
try:
    from sqliter import sqliter #sqliter.py
    from sqliter import Where, SQLRawExpression
except ImportError:
    import sqliter
    from sqliter.sqliter import Where, SQLRawExpression #sqliter.py

APP_NAME = 'wordpress-notifier'
AUTHOR = 'Atlas'
APP_VERSION = 1

TBL_WP_VER = sqliter.DatabaseTable()
TBL_WP_VER.name = 'cur_wordpres_ver'
TBL_WP_VER.set_cols((('version', 'TEXT PRIMARY KEY'),))

TBL_PLUGINS_VER = sqliter.DatabaseTable()
TBL_PLUGINS_VER.name = 'cur_plugins_ver'
TBL_PLUGINS_VER.set_cols((('id', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
                          ('plugin_url', 'TEXT'),
                          ('version', 'TEXT')))

class NoWordPressVersionSetError(Exception):
    """No WP version has been set"""
    pass

class NoPluginVersionSetError(Exception):
    """No version has been set for specified plugin"""
    pass

class DatabaseConnection(object):
    """Connection to database"""
    def __init__(self):
        self.con = sqliter.DatabaseConnection(
            db_tables=[TBL_WP_VER, TBL_PLUGINS_VER],
            app_tuple=(APP_NAME, AUTHOR, APP_VERSION))

    def __enter__(self):
        return self

    def __exit__(self, exec_type, exec_value, exec_traceback):
        self.con = None #TODO do something else to close db

    def get_wp_version(self):
        """Get current WordPress version

        Raises: NoWordPressVersionSetError
        """
        record = self.con.select(col_names=['version'], db_table=TBL_WP_VER)
        if len(record) == 0:
            raise NoWordPressVersionSetError()
        else:
            return record[0]['version']

    def set_wp_version(self, version):
        """Set current WordPress version"""
        try:
            self.get_wp_version()
            self.con.update(db_table=TBL_WP_VER, col_val_map={'version': version})
        except NoWordPressVersionSetError:
            self.con.insert(db_table=TBL_WP_VER, col_val_map={'version': version})

    def get_plugin_version(self, plugin_url):
        """Get current version for a specific WP plugin, index by URL

        Raises: NoPluginVersionSetError
        """
        where = Where(TBL_PLUGINS_VER)
        record = self.con.select(col_names=['version'],
                                 where=where.eq('plugin_url', plugin_url))
        if len(record) == 0:
            raise NoPluginVersionSetError()
        else:
            return record[0]['version']

    def set_plugin_version(self, plugin_url, version):
        """Set current version for a specific WP plugin, indexed by URL"""
        try:
            self.get_plugin_version(plugin_url)
            where = Where(TBL_PLUGINS_VER)
            self.con.update(col_val_map={'version': version},
                            where=where.eq('plugin_url', plugin_url))
        except NoPluginVersionSetError:
            record = {'plugin_url': plugin_url, 'version': version}
            self.con.insert(db_table=TBL_PLUGINS_VER, col_val_map=record)

    def get_plugin_urls(self):
        """Get a set of unique plugin URLs

        Raises: NoPluginVersionSetError
        """
        records = self.con.select(col_names=['plugin_url'],
                                  db_table=TBL_PLUGINS_VER)
        if len(records) == 0:
            raise NoPluginVersionSetError()

        urls = set()
        for record in records:
            urls.add(record['plugin_url'])
        return urls

    def remove_plugin(self, url):
        """Remove plugin from list of installed plugins to montior"""
        raise NotImplementedError() #TODO

def debug():
    """Used for debugging...

    Todos: Move this section to unit tests.
    """
    from random import randint
    ver = 'v{0}'.format(str(randint(0, 99)))

    with DatabaseConnection() as con:
        try:
            print "Current WP version: {0}".format(con.get_wp_version())
            print "Updating to random value..."
            con.set_wp_version(ver)

        except NoWordPressVersionSetError:
            print "No WordPress version stored as of yet. Storing random value..."

            print "Storing WordPress version as {0}".format(ver)
            con.set_wp_version(ver)

        print "Stored WP version: {0}".format(con.get_wp_version())

        ver = 'v{0}'.format(str(randint(0, 99999999)))

        try:
            url = 'https://wordpress.org/plugins/jetpack/'
            print "Current WP version for {0}: {1}".format(url, con.get_plugin_version(url))
            print "Updating to random value..."
            con.set_plugin_version(url, ver)
        except NoPluginVersionSetError:
            print "No version stored for {0} yet. Storing random value...".format(url)

            print "Storing plugin version as {0}".format(ver)
            con.set_plugin_version(url, ver)

        print "Stored plugin version: {0}".format(con.get_plugin_version(url))

if __name__ == '__main__':
    debug()
