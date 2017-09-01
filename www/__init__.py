"""Fetch latest version available of WP and plugins from web"""

#THIS IS (Python Standard) LIBRARY 2.7
import re

#PyPI
import requests

WORDPRESS_VERSION_URL = 'https://github.com/WordPress/WordPress/releases'

class UnsupportedURLError(Exception):
    """Not a supported plugin url"""
    pass

class CannotFetchWordpressVersionError(Exception):
    """Couldn't pull wordpress version from GitHub"""

class CannotFetchPluginVersionError(Exception):
    """Couldn't pull plugin version from web"""

def get_wp_version():
    """Fetch the latest version of WordPress

    Raises: CannotFetchWordpressVersionError
    """
    resp = requests.get(WORDPRESS_VERSION_URL)
    assert resp.status_code == 200
    match = re.search(r'/WordPress/WordPress/releases/tag/([^"]+)"', resp.text)
    if match is not None:
        return match.group(1)
    else:
        raise CannotFetchWordpressVersionError()

def get_plugin_version(url):
    """Fetch the latest version of the specified WordPress plugin

    Raises: CannotFetchPluginVersionError
    """
    if not url.startswith('https://wordpress.org/plugins/'):
        raise UnsupportedURLError()

    resp = requests.get(url)
    assert resp.status_code == 200
    match = re.search(r'"softwareVersion":\s*"([^"]+)"', resp.text)
    if match is not None:
        return match.group(1)
    else:
        raise CannotFetchPluginVersionError()

def _debug():
    print get_wp_version()
    print get_plugin_version('https://wordpress.org/plugins/jetpack/')

if __name__ == '__main__':
    _debug()
