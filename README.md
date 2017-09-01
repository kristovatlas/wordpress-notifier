# wordpress-notifier

Receive email updates when WordPress or plugins are updated

## Requirements

This program relies on the twoifbysea local web service.

https://github.com/kristovatlas/twoifbysea

## Usage and Configuration

    $ python util.py --set-wordpress-version 4.8.1

    $ python util.py --set-plugin-version https://wordpress.org/plugins/jetpack/ 5.2.1

    $ python app.py recipient@example.com

Requires the following environment variables to be set:
* `TWOIFBYSEA_DEFAULT_GMAIL_USERNAME`
* `TWOIFBYSEA_DEFAULT_GMAIL_PASSWORD`

## TODOs

* Permit listing of multiple recipients as command-line argument to app.py.
* Unit tests
* Add feature that detects current WP version on target site using default installation files, rather than requiring manual updating of version status using `util.py`.
* Refactor amount of code required on client side for twoifbysea and/or implement proper system installation
