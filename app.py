"""Check latest version of WordPress and plugins; send email if updated.

Requires the following environment variables to be set:
* TWOIFBYSEA_DEFAULT_GMAIL_USERNAME
* TWOIFBYSEA_DEFAULT_GMAIL_PASSWORD

Usage:
    $ python app.py recipient@example.com
"""
#Python Standard Library 2.7
import sys

#wordpress-notifier
import db
import www

#twoifbysea modules
from twoifbysea import connectors, common

WP_VER_SUBJECT = 'There is an update to WordPress: {version} (wordpress-notifier)'
PLUGIN_VER_SUBJECT = ('There is an update to WordPress plugin {url}: {version} '
                      '(wordpress-notifier)')
NO_WP_VER_SUBJECT = 'No WordPress version has been stored (wordpress-notifier)'
NOFETCH_WP_SUBJECT = ('Unable to check current WordPress version '
                      '(wordpress-notifier)')
NOFETCH_PLUGIN_SUBJECT = ('Unable to check current version of WordPress '
                          'Plugin: {url} (wordpress-notifier)')

WP_VER_MESSAGE = (
    'WordPress has been updated to version {version}. You have an older '
    'version, {old_version} installed. Once you have updated your '
    'installation, you can manually update this status in wordpress-notifier '
    'using the util.py script. This email was generated using '
    'https://github.com/kristovatlas/wordpress-notifier')

PLUGIN_VER_MESSAGE = (
    'A WordPress plugin has been updated.\n\n'
    'URL: {url}\n\n'
    'Current version installed: {old_version}\n\n'
    'Version available: {version}\n\n'
    'Once you have updated your installation, you can manually update this '
    'status in wordpress-notifier using the util.py script.\n\n'
    'This email was generated using '
    'https://github.com/kristovatlas/wordpress-notifier')

NO_WP_VER_MESSAGE = (
    'You have not yet stored a version of WordPress, but the script checking '
    'for updates has been run. Please store your currently deployed version of '
    'WordPress using the util.py script.\n\n'
    'This email was generated using '
    'https://github.com/kristovatlas/wordpress-notifier')

NOFETCH_WP_MESSAGE = (
    'An error occurred while trying to check the current version of WordPress '
    'available on the web. You may want to investigate the cause of this '
    'error.\n\n'
    'This email was generated using '
    'https://github.com/kristovatlas/wordpress-notifier')

NOFETCH_PLUGIN_MESSAGE = (
    'An error occurred while trying to check the the current version of a '
    'WordPress plugin.\n\n'
    'URL: {url}\n\n'
    'You may want to investigate the cause of this error.\n\n'
    'This email was generated using '
    'https://github.com/kristovatlas/wordpress-notifier')

def _get_recipients(argv):
    if len(argv) != 2:
        _usage()
    return [argv[1]]

def _usage():
    print ("Usage:\n"
           "\t$ python app.py recipient@example.com")
    sys.exit(1)

def _main(argv):
    recipients = _get_recipients(argv)

    #Get list of versions stored in db
    wp_version = None
    plugin_url_to_ver = {}
    with db.DatabaseConnection() as con:
        try:
            wp_version = con.get_wp_version()
            print "Current version of WordPress stored is: {0}".format(wp_version)
        except db.NoWordPressVersionSetError:
            print "No version for WordPress has been stored. Skipping..."
            email(recipients=recipients, subject=NO_WP_VER_SUBJECT,
                  body=NO_WP_VER_MESSAGE)

        try:
            urls = con.get_plugin_urls()
            print "WordPress plugins:"
            for url in urls:
                plugin_version = con.get_plugin_version(url)
                plugin_url_to_ver[url] = plugin_version
                print "\t{0}: {1}".format(url, plugin_version)
        except db.NoPluginVersionSetError:
            print "No WordPress plugin versions have been stored. Skipping..."

    #Check latest versions from www
    try:
        wp_version_latest = www.get_wp_version()
        if wp_version_latest == wp_version:
            print "WordPress is up to date."
        else:
            print "WordPress is not up to date. Current: {0} Latest: {1}".format(
                wp_version, wp_version_latest)
            email(recipients=recipients,
                  subject=WP_VER_SUBJECT.format(version=wp_version_latest),
                  body=WP_VER_MESSAGE.format(
                      version=wp_version_latest, old_version=wp_version))
    except www.CannotFetchWordpressVersionError:
        print "Error: Unable to retrieve current version of WordPress available."
        email(recipients=recipients, subject=NOFETCH_WP_SUBJECT,
              body=NOFETCH_WP_MESSAGE)

    for plugin_url in plugin_url_to_ver:
        try:
            plugin_version_latest = www.get_plugin_version(plugin_url)
            if plugin_url_to_ver[plugin_url] == plugin_version_latest:
                print "WordPress plugin {0} is up to date.".format(plugin_url)
            else:
                print ("WordPress plugin {0} is not up to date. Current: {1} "
                       "Latest: {2}").format(plugin_url,
                                             plugin_url_to_ver[plugin_url],
                                             plugin_version_latest)
                email(recipients=recipients,
                      subject=PLUGIN_VER_SUBJECT.format(
                          url=plugin_url, version=plugin_version_latest),
                      body=PLUGIN_VER_MESSAGE.format(
                          url=plugin_url, version=plugin_version_latest,
                          old_version=plugin_url_to_ver[plugin_url]))
        except www.CannotFetchPluginVersionError:
            print "Unable to fetch version for plugin {0}".format(plugin_url)
            email(recipients=recipients,
                  subject=NOFETCH_PLUGIN_SUBJECT.format(url=plugin_url),
                  body=NOFETCH_PLUGIN_MESSAGE.format(url=plugin_url))


def email(recipients, subject, body):
    """Send alert email"""
    print 'Send email to {0} (Subject: "{1}")'.format(recipients[0], subject)

    with connectors.HTTPConnector() as con:
        con.notify(subject=subject, body=body,
                   recipients=recipients, channel=common.SupportedChannels.GMAIL,
                   error_channel=common.SupportedChannels.GMAIL,
                   error_recipients=recipients)

if __name__ == '__main__':
    _main(sys.argv)
