"""Utility for managing database.

Usage:
    $ python util.py --set-wordpress-version 4.8.1
    $ python util.py --set-plugin-version https://wordpress.org/plugins/jetpack/ 5.2.1
"""

#Python Standard Library 2.7
import sys

#wordpress-notifier
try:
    from db import db
except ImportError:
    import db

class ModeArgs(object):
    """Parse argv"""

    MODES = {'SET_WP_VERSION': 1,
             'SET_PLUGIN_VERSION': 2}

    def __init__(self, argv):
        if len(argv) == 3 and argv[1] == '--set-wordpress-version':
            self.mode = self.MODES['SET_WP_VERSION']
            self.version = argv[2]
        elif (len(argv) == 4 and argv[1] == '--set-plugin-version' and
              argv[2].startswith('http')):
            self.mode = self.MODES['SET_PLUGIN_VERSION']
            self.url = argv[2]
            self.version = argv[3]
        else:
            _usage()

def _main(argv):
    #Parse argv
    mode_args = ModeArgs(argv)

    #Connect to db
    with db.DatabaseConnection() as con:

        if mode_args.mode == ModeArgs.MODES['SET_WP_VERSION']:
            con.set_wp_version(mode_args.version)
            print "Set WordPress version to {0}".format(con.get_wp_version())

        elif mode_args.mode == ModeArgs.MODES['SET_PLUGIN_VERSION']:
            con.set_plugin_version(mode_args.url, mode_args.version)
            print "Set Plugin {0} version to {1}".format(
                mode_args.url, con.get_plugin_version(mode_args.url))

def _usage():
    print ("Example usage:\n"
           "\t$ python util.py --set-wordpress-version 4.8.1\n"
           "\t$ python util.py --set-plugin-version "
           "https://wordpress.org/plugins/jetpack/ 5.2.1\n")
    sys.exit(1)

if __name__ == '__main__':
    _main(sys.argv)
