#!/bin/bash

function help()
{
    echo "Script: setup.sh"
    echo ""
    echo "Purpose:"
    echo "  1)  Generate VPN Keys"
    echo "  2)  Fetch Archiver Key"
    echo "  3)  Fetch Static IP"
    echo ""
    echo "Syntax: $0 <option>"
    echo "option:"
    echo "  -h  Show this help"
    echo "  -v  controller vpn name"
    echo "  -a  client archiver name"
    echo "  -s  controller vpn name"

}

function vpngenerate()
{
    if [[ -e /etc/openvpn/easy-rsa/keys/$VPN_NAME.key || -e /etc/openvpn/easy-rsa/keys/$VPN_NAME.crt ]]
    then
        echo "$VPN_NAME already exist"
    else
        echo "$VPN_NAME does not exist"

        echo "Generating keys"
        cd /etc/openvpn/easy-rsa/ && printf '\n\n\n\n\n\n\n' | ./easyrsa gen-req $VPN_NAME nopass
        cd /etc/openvpn/easy-rsa/ && printf 'yes' | ./easyrsa --passin='pass:xitanez123!@#' sign-req client $VPN_NAME
        cp /etc/openvpn/easy-rsa/pki/private/$VPN_NAME.key /etc/openvpn/easy-rsa/keys
        cp /etc/openvpn/easy-rsa/pki/issued/$VPN_NAME.crt /etc/openvpn/easy-rsa/keys
        chmod 644 /etc/openvpn/easy-rsa/keys/$VPN_NAME*

        echo "Assigning static IP"
        cd /root/src/vpn_certificate_api/ && python3 assign_static_ip.py
    fi
}

function vpngenerate_with_given_ip()
{
    if [[ -e /etc/openvpn/easy-rsa/keys/$VPN_NAME.key || -e /etc/openvpn/easy-rsa/keys/$VPN_NAME.crt ]]
    then
        echo "$VPN_NAME already exist"
    else
        echo "$VPN_NAME does not exist"

        echo "Generating keys"
        cd /etc/openvpn/easy-rsa/ && printf '\n \n \n \n \n \n \n' | ./easyrsa gen-req $VPN_NAME nopass
        cd /etc/openvpn/easy-rsa/ && printf 'yes' | ./easyrsa --passin='pass:xitanez123!@#' sign-req client $VPN_NAME
        cp /etc/openvpn/easy-rsa/pki/private/$VPN_NAME.key /etc/openvpn/easy-rsa/keys
        cp /etc/openvpn/easy-rsa/pki/issued/$VPN_NAME.crt /etc/openvpn/easy-rsa/keys
        chmod 644 /etc/openvpn/easy-rsa/keys/$VPN_NAME*

        echo "Assigning static IP"
        echo "ifconfig-push $CLIENT_IP $SERVER_IP" > /etc/openvpn/ccd/"$VPN_NAME"
    fi
}

function archiverget()
{	docker exec powerdb2-prod python manage.py get_key $ARCHIVER_NAME
}

function staticipget()
{
	cd /root/src/vpn_certificate_api/ && python3 assign_static_ip.py
	vpn_file_name=`ls /etc/openvpn/ccd/ | grep -w "^$VPN_NAME$"`
	#echo $vpn_file_name
	cat /etc/openvpn/ccd/$vpn_file_name | cut -d ' ' -f2
}

function controller_ip() {
    TUN_IP_PREFIX=$(echo $TUN_IP | cut -d '.'  -f 1-2)
    cat /etc/openvpn/openvpn-status.log | grep "^$TUN_IP_PREFIX" | grep ",$VPN_NAME," | cut -d "," -f1
}

# This function will parse the command line option
parseCmd()
{
	while getopts "h:v:a:s:i:c:" OPTION
	do
		case "$OPTION" in
	        h) # Help option
	            help
	            exit 0
	            ;;
	        v) # controller vpn name
	            VPN_NAME=${OPTARG}
	            vpngenerate
	            ;;
	        i) # controller vpn name and static IP
	            VPN_NAME=$(echo "${OPTARG}" | cut -d '/' -f 1)
	            CLIENT_IP=$(echo "${OPTARG}" | cut -d '/' -f 2)
	            SERVER_IP=$(echo "${OPTARG}" | cut -d '/' -f 3)
	            vpngenerate_with_given_ip
	            ;;
	        a) # archiver name
	            ARCHIVER_NAME=${OPTARG}
	            archiverget
	            ;;
	        s) # static ip
	            VPN_NAME=${OPTARG}
	            staticipget
	            ;;
	        c) # controller ip
	            VPN_NAME=${OPTARG}
	            controller_ip
	            ;;
		esac
	done
}

parseCmd $*
