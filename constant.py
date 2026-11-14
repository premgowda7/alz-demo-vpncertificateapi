"""
@author Tarun Malviya <tarun.malviya@zenatix.com>
"""

import os
VPN_CERTIFICATE_PATH = '/etc/openvpn/easy-rsa/keys/{}.{}'
VPN_IP_PATH = '/etc/openvpn/ccd/'
VPN_CERTIFICATE_DIR = '/etc/openvpn/easy-rsa/keys/'
OLD_CERT_BACKUP_DIR = '/etc/openvpn/easy-rsa/backup/'
OPENVPN_STATUS_LOG_FILE = '/etc/openvpn/openvpn-status.log'
ROLLOUT_STATUS_DIR = '/etc/openvpn/easy-rsa/rollout_status'

REQUEST_PUT = "PUT"
REQUEST_POST = "POST"
REQUEST_GET = "GET"

AUTHORISATION_TOKEN = os.environ.get("AUTHORISATION_TOKEN", "")
