"""
@author Tarun Malviya <tarun.malviya@zenatix.com> and Parth Goel <parth.goel@zenatix.com>
"""
import glob
import os
import json
import shutil
import socket
from io import BytesIO
from os.path import basename
import zipfile
import subprocess
from flask import Flask, request, send_file, jsonify, make_response, send_from_directory
from constant import VPN_CERTIFICATE_PATH, VPN_IP_PATH, VPN_CERTIFICATE_DIR, OLD_CERT_BACKUP_DIR, \
    OPENVPN_STATUS_LOG_FILE, REQUEST_GET, AUTHORISATION_TOKEN, ROLLOUT_STATUS_DIR

app = Flask(__name__)


@app.route('/')
def index():
    return 'Welcome to VPN Certificate API!'


def execute_shell_command(cmd):
    if cmd:
        try:
            output = subprocess.check_output(cmd.split(" "))
            return output.strip(), 0
        except Exception:
            return "NA", -1
    else:
        return "NA", -1


def zip_vpn_certificates(crt_file_path, key_file_path):
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(crt_file_path, basename(crt_file_path.split('/')[-1]))
        zf.write(key_file_path, basename(key_file_path.split('/')[-1]))
    # To 'rewind' the read-write position of the file object back to the start.
    memory_file.seek(0)
    return memory_file


def validate_ip_address(ip_address):
    if ip_address is None:
        return False
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False


def get_file_content(path, file):
    with app.test_request_context():
        with app.app_context():
            return send_from_directory(path, file).response.file.read().decode().strip()


@app.route('/openvpn/v1/download_vpn_certificates/<vpn_cert_name>/', methods=[REQUEST_GET])
def download_vpn_certificates(vpn_cert_name):
    if request.headers.get('Authorization', '') != AUTHORISATION_TOKEN:
        return jsonify({'status': False, 'error': 'Unauthorized access'})

    zip_file_name = '{}_vpn_certificates.zip'.format(vpn_cert_name)
    crt_file_path = "{}{}.crt".format(VPN_CERTIFICATE_DIR, vpn_cert_name)
    key_file_path = "{}{}.key".format(VPN_CERTIFICATE_DIR, vpn_cert_name)
    ccd_file_path = "{}{}".format(VPN_IP_PATH, vpn_cert_name)

    if not os.path.isfile(crt_file_path) and not os.path.isfile(key_file_path):
        return jsonify({'status': False, 'error': 'VPN certificates do not exist for {}'.format(vpn_cert_name)})

    if not os.path.isfile(ccd_file_path):
        return jsonify({'status': False, 'error': 'Static IP does not exist for {}'.format(vpn_cert_name)})

    memory_file = zip_vpn_certificates(crt_file_path, key_file_path)
    response = make_response(send_file(memory_file,
                                       mimetype='zip',
                                       attachment_filename=zip_file_name,
                                       as_attachment=True))
    vpn_ip_address = get_file_content(VPN_IP_PATH, vpn_cert_name).split(' ')[1]
    response.headers['vpn_ip_address'] = vpn_ip_address
    return response


@app.route('/openvpn/v1/get_vpn_certificates/<vpn_cert_name>/', methods=[REQUEST_GET])
def get_vpn_certificates(vpn_cert_name):
    if request.headers.get('Authorization', '') != AUTHORISATION_TOKEN:
        return jsonify({'status': False, 'error': 'Unauthorized access'})

    ca_crt_file_name = "ca.crt"
    crt_file_name = "{}.crt".format(vpn_cert_name)
    key_file_name = "{}.key".format(vpn_cert_name)
    ccd_file_name = vpn_cert_name

    ca_crt_file_path = "{}{}".format(VPN_CERTIFICATE_DIR, ca_crt_file_name)
    crt_file_path = "{}{}".format(VPN_CERTIFICATE_DIR, crt_file_name)
    key_file_path = "{}{}".format(VPN_CERTIFICATE_DIR, key_file_name)
    ccd_file_path = "{}{}".format(VPN_IP_PATH, ccd_file_name)

    if not os.path.isfile(crt_file_path) and not os.path.isfile(key_file_path):
        cmd = "./vpn_setup.sh -v {}".format(vpn_cert_name)
        print("Executing command -> {}".format(cmd))
        op, returncode = execute_shell_command(cmd)
        print("Return code -> {}.".format(returncode))
        print("Output -> {}.".format(op))
        if returncode:
            return jsonify({'status': False, 'error': 'Failed to generate vpn certificates'})

    if not os.path.isfile(ca_crt_file_path) or os.path.getsize(ca_crt_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(ca_crt_file_name)})

    if not os.path.isfile(crt_file_path) or os.path.getsize(crt_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(crt_file_name)})

    if not os.path.isfile(key_file_path) or os.path.getsize(key_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(key_file_name)})

    if not os.path.isfile(ccd_file_path) or os.path.getsize(ccd_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(ccd_file_path)})

    ca_crt_file_content = get_file_content(VPN_CERTIFICATE_DIR, ca_crt_file_name)

    crt_file_content = get_file_content(VPN_CERTIFICATE_DIR, crt_file_name)

    key_file_content = get_file_content(VPN_CERTIFICATE_DIR, key_file_name)

    vpn_ip_address = get_file_content(VPN_IP_PATH, ccd_file_name).split(' ')[1]
    if not validate_ip_address(vpn_ip_address):
        return jsonify({'status': False, 'error': 'Valid VPN IP address does not exist in file {}'.format(
            ccd_file_path)})

    response = jsonify({'status': True,
                        ca_crt_file_name: ca_crt_file_content,
                        crt_file_name: crt_file_content,
                        key_file_name: key_file_content,
                        'IPv4Address': vpn_ip_address
                        })
    return response


@app.route('/vpn_certificate_api/<controller>/<extension>/', methods=[REQUEST_GET])
def vpn_certificate_api(controller, extension):
    if request.headers.get('Authorization', '') != AUTHORISATION_TOKEN:
        return str({'error': 'Unauthorized access'})

    if extension not in ['crt', 'key']:
        return str({'error': 'Bad file extension.'})

    path = VPN_CERTIFICATE_PATH.format(controller, extension)
    if not os.path.isfile(path):
        return str({'error': 'File does not exists.'})

    return send_file(path)


@app.route('/vpn_ip_api/', methods=[REQUEST_GET])
def vpn_ip_api():
    if request.headers.get('Authorization', '') != AUTHORISATION_TOKEN:
        return str({'error': 'Unauthorized access'})

    path = VPN_IP_PATH
    vpn_ip_dict = {}
    try:
        vpn_ip_abs_file_names = glob.glob(os.path.join(path, '*'))
        for abs_file_name in vpn_ip_abs_file_names:
            static_ip = get_file_content(path, abs_file_name.split('/')[-1]).split(' ')[1]
            vpn_key_name = abs_file_name.split('/')[-1]
            vpn_ip_dict[vpn_key_name] = static_ip
    except Exception as e:
        vpn_ip_dict['error'] = str(e)

    return jsonify(vpn_ip_dict)


@app.route('/openvpn/v1/get_vpn_certificates_with_give_static_ip/', methods=[REQUEST_GET])
def get_vpn_certificates_with_give_static_ip():
    if request.headers.get('Authorization', '') != AUTHORISATION_TOKEN:
        return jsonify({'status': False, 'error': 'Unauthorized access'})

    vpn_cert_name = request.args.get('vpn_cert_name', None)
    static_ip = request.args.get('static_ip', None)
    vpn_key_name = None
    try:
        vpn_ip_abs_file_names = glob.glob(os.path.join(VPN_IP_PATH, '*'))
        for abs_file_name in vpn_ip_abs_file_names:
            if static_ip == get_file_content(VPN_IP_PATH, abs_file_name.split('/')[-1]).split(' ')[1]:
                vpn_key_name = abs_file_name.split('/')[-1]
            if vpn_key_name:
                if not os.path.exists(OLD_CERT_BACKUP_DIR):
                    os.makedirs(OLD_CERT_BACKUP_DIR)
                if not os.path.exists(OLD_CERT_BACKUP_DIR + vpn_key_name + '/'):
                    os.makedirs(OLD_CERT_BACKUP_DIR + vpn_key_name + '/')
                shutil.move(VPN_IP_PATH + vpn_key_name, OLD_CERT_BACKUP_DIR + vpn_key_name + '/' + vpn_key_name)
                shutil.move(VPN_CERTIFICATE_PATH.format(vpn_key_name, 'crt'),
                            OLD_CERT_BACKUP_DIR + vpn_key_name + '/' + vpn_key_name + '.crt')
                shutil.move(VPN_CERTIFICATE_PATH.format(vpn_key_name, 'csr'),
                            OLD_CERT_BACKUP_DIR + vpn_key_name + '/' + vpn_key_name + '.csr')
                shutil.move(VPN_CERTIFICATE_PATH.format(vpn_key_name, 'key'),
                            OLD_CERT_BACKUP_DIR + vpn_key_name + '/' + vpn_key_name + '.key')
                break
    except Exception as e:
        return jsonify({'status': False, 'error': str(e)})

    ca_crt_file_name = "ca.crt"
    crt_file_name = "{}.crt".format(vpn_cert_name)
    key_file_name = "{}.key".format(vpn_cert_name)
    ccd_file_name = vpn_cert_name

    ca_crt_file_path = "{}{}".format(VPN_CERTIFICATE_DIR, ca_crt_file_name)
    crt_file_path = "{}{}".format(VPN_CERTIFICATE_DIR, crt_file_name)
    key_file_path = "{}{}".format(VPN_CERTIFICATE_DIR, key_file_name)
    ccd_file_path = "{}{}".format(VPN_IP_PATH, ccd_file_name)

    server_static_ip = static_ip.rsplit('.', 1)[0] + '.' + str(int(static_ip.split('.')[-1]) + 1)
    vpn_generate_argument = vpn_cert_name + '/' + static_ip + '/' + server_static_ip
    if not os.path.isfile(crt_file_path) and not os.path.isfile(key_file_path):
        cmd = "./vpn_setup.sh -i {}".format(vpn_generate_argument)
        print("Executing command -> {}".format(cmd))
        op, returncode = execute_shell_command(cmd)
        print("Return code -> {}.".format(returncode))
        print("Output -> {}.".format(op))
        if returncode:
            return jsonify({'status': False, 'error': 'Failed to generate vpn certificates'})

    if not os.path.isfile(ca_crt_file_path) or os.path.getsize(ca_crt_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(ca_crt_file_name)})

    if not os.path.isfile(crt_file_path) or os.path.getsize(crt_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(crt_file_name)})

    if not os.path.isfile(key_file_path) or os.path.getsize(key_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(key_file_name)})

    if not os.path.isfile(ccd_file_path) or os.path.getsize(ccd_file_path) == 0:
        return jsonify({'status': False, 'error': '{} file does not exist or is empty'.format(ccd_file_path)})

    ca_crt_file_content = get_file_content(VPN_CERTIFICATE_DIR, ca_crt_file_name)

    crt_file_content = get_file_content(VPN_CERTIFICATE_DIR, crt_file_name)

    key_file_content = get_file_content(VPN_CERTIFICATE_DIR, key_file_name)

    vpn_ip_address = get_file_content(VPN_IP_PATH, ccd_file_name).split(' ')[1]
    if not validate_ip_address(vpn_ip_address):
        return jsonify({'status': False, 'error': 'Valid VPN IP address does not exist in file {}'.format(
            ccd_file_path)})

    response = jsonify({'status': True,
                        ca_crt_file_name: ca_crt_file_content,
                        crt_file_name: crt_file_content,
                        key_file_name: key_file_content,
                        'IPv4Address': vpn_ip_address
                        })
    return response


@app.route('/controller_status_and_ip/<controller>/', methods=[REQUEST_GET])
def controller_status_and_ip(controller):
    if request.headers.get('Authorization', '') != AUTHORISATION_TOKEN:
        return str({'error': 'Unauthorized access'})

    output, returncode = execute_shell_command(f'./vpn_setup.sh -c {controller}')

    if returncode == 0:
        output = output.decode()
        TUN_IP = os.environ['TUN_IP']
        TUN_IP_PREFIX = TUN_IP.split('.')[0] + '.' + TUN_IP.split('.')[1]
        if output == '':
            status = True
            controller_status = 'offline'
        elif output.startswith(TUN_IP_PREFIX):
            status = True
            controller_status = 'online'
        else:
            status = False
            controller_status = ''
        response = jsonify({'status': status, 'controller_status': controller_status, 'IP': output})
    else:
        status = False
        controller_status = ''
        response = jsonify({'status': status, 'controller_status': controller_status})

    return response


@app.route('/rollout_status/<controller>/<status>', methods=[REQUEST_GET])
def rollout_status(controller, status):
    try:
        if request.headers.get('Authorization', '') != AUTHORISATION_TOKEN:
            return str({'error': 'Unauthorized access'})

        if status not in ['1', '0']:
            return str({'error': 'Invalid status, status should be 1 or 0.'})
        if not os.path.exists(ROLLOUT_STATUS_DIR):
            os.makedirs(ROLLOUT_STATUS_DIR)

        with open('{}/{}.json'.format(ROLLOUT_STATUS_DIR, controller), 'w') as outfile:
            outfile.write(json.dumps({"controller": controller, "status": bool(int(status))}))
            outfile.close()
    except Exception as e:
        return str({'status': False, 'message': str(e)})

    return jsonify({'status': True, 'message': ""})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
