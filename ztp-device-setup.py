"""
ztp-device-setup.py
ZTP Device setup from Spreadsheet
"""
import warnings
import requests
import json
import logging
import sys
import re
import csv
import base64
import argparse
import shutil
import jinja2
from os.path import exists
from logging import getLogger, Formatter, StreamHandler
from pandas import read_csv, concat

# Static Variables - to be moved into separate file
CROSSWORK_VIP = "192.168.131.233"
CROSSWORK_PORT = "30604"
EPNM_IP = "172.16.206.66"
EPNM_USERNAME = "copyOfCisco_AES256"
EPNM_PASSWORD = "Abc12345"
EPNM_CRED_POLICY = "epnm_cre"
ENV_FILE = "./env/profiles.json"
ENV_PROFILE = "233-SWR-742-ZTP"
CPNR_URL = "https://localhost:8443"
ZTP_SCRIPT = 'ztp-script' # ztp script name in cnc for DHCP


# Setup input arguments
parser = argparse.ArgumentParser(description='Crossworks ZTP Device Setup program.')

parser.add_argument('-batch', help="Generate ZTP Devices by batch id", type=str, required=True)
parser.add_argument('--create', help="Run ZTP Device turn-up process for batch id", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--device_creation', help="Add ZTP Device into CNC", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--enable', help="Create DHCP entries in CPNR", action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--show_process', help="Show the ZTP Device turn-up process", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--use_profiles', help="Use ZTP Profiles for each device", action=argparse.BooleanOptionalAction, default=False)

args = parser.parse_args()

# Enabling logging
log = getLogger("%s" % "ZTP Device turn-up")
formatter = Formatter(
" ".join(
        [
        "%(asctime)s",
        "%(levelname)s",
        "%(name)s:",
        "%(module)s",
        "(%(lineno)d)::",
        "%(message)s",
        ]
    )
)
console_handler = StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.DEBUG)
log.setLevel(logging.DEBUG)
log.addHandler(console_handler)

def read_env_properties(filename, profile_name):
    ''' Read Env properties with profile selection and validation '''
    try:
        properties_file = open(filename, "r")
        properties_data = json.load(properties_file)
        profile = properties_data[profile_name]
        response = profile
        
        # Check for device_file
        if not exists(profile['device_file']):
            print('Environment profile error - Devices file does not exist: ' + profile['device_file'])
            response = False

        # Check for config_template_file
        if not exists(profile['config_template_file']):
            print('Environment profile error - Config template file does not exist: ' + profile['config_template_file'])
            response = False

        # Check for correct format for is_secure_ztp
        if (profile['is_secure_ztp'] != 'true' and profile['is_secure_ztp'] != 'false'):
            print('Environment profile error - Use "true" or "false" for key "is_secure_ztp"')
            response = False

        # Check for vouchers_folder if secure ztp is used
        if (profile['is_secure_ztp'] == 'true'):
            if not exists(profile['vouchers_folder']):
                print('Environment profile error - Vouchers file does not exist: ' + profile['vouchers_folder'])
                response = False
        warnings.filterwarnings('ignore')

    except Exception as e:
        log.error("Could not read environment properties from {}" .format(filename))
        log.debug("Exception {} occurred." .format(e.__class__))
        return False

    return response

# def verify_devices_input(devices_dict): - to do


def generate_ticket(cw_url, cw_user, cw_pass):
    ''' Generate Crosswork ticket '''
    url = cw_url + '/crosswork/sso/v1/tickets'
    params = {'username': cw_user, 'password': cw_pass}
    payload = ""
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'text/plain',
    'Cache-Control': 'no-cache'
    }
    
    try:
        response = requests.request("POST", url, params=params, headers=headers, data=payload, verify=False)
        ticket = response.text
        if (response.status_code == 401):
            print(response.text['authentication_exceptions'])
            return False
        return ticket
    except Exception as e:
        log.error("API Authentication - Retrieval of CNC ticket from {} failed!" .format(cw_url))
        log.debug("Exception {} occurred." .format(e.__class__))
        return False


def generate_token(cw_url, ticket):
    ''' Generate Crosswork token '''
    url = cw_url + "/crosswork/sso/v1/tickets/" + ticket
    payload='service=https%3A%2F%2F172.23.193.107%3A30603%2Fapp-dashboard'
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'text/plain',
    'Cache-Control': 'no-cache'
    }

    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        token = response.text
        return token

    except Exception as e:
        log.error("API Authentication - Retrieval of CNC token from {} failed!" .format(cw_url))
        log.debug("Exception {} occurred." .format(e.__class__))
        return False


def create_config_from_template(filename, template, data):
    ''' Create a config file from config file template '''
    try:
        f = open(filename, "w")
        f.write(template.render(data)) # Jinja2 Template 
        f.close
        
        print("Config File created at: {}" .format(filename))
        return True
    except Exception as e:
        log.error("Failed to create file: {}" .format(filename))
        log.debug("Exception {} occurred." .format(e.__class__))
        return False


def check_serial_number(cw_url, token, serial_number):
    ''' Query device serial number in crossworks. Return serial number if exist. '''
    url = cw_url + '/crosswork/ztp/v1/serialnumbers/query'

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    payload = json.dumps({
        "filter": {
            "serialNumber": "*" + serial_number
        }
    })

    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        if 'data' in response.json():
            data =  response.json()['data']
            for cnc_serial_number in data:
                if cnc_serial_number['serialNumber'] == serial_number:
                    return cnc_serial_number
        return False
    except Exception as e:
        log.error("ZTP Serial nubmer query failed!")
        log.debug("Exception {} occurred." .format(e.__class__))

    return False

def add_serial_number(cw_url, token, serial_number):
    ''' Add serial number '''
    url = cw_url + '/crosswork/ztp/v1/serialnumbers'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    payload = json.dumps({"data": [
    {
      "serialNumber": serial_number
    }
    ]})
    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        print("Serial Number Added: " + serial_number)
        return True

    except Exception as e:
        log.error("Add ZTP Serial nubmer: {} failed!".format(serial_number))
        log.debug("Exception {} occurred." .format(e.__class__))

    return False

def add_ownership_voucher(cw_url, token, file_name, vouchers_path):
    url = cw_url + '/crosswork/ztp/v1/ovs/import'
    file_path = vouchers_path + file_name

    # base64 encoded voucher
    try: 
        with open(file_path, "rb") as voucher:
            encoded_string = base64.b64encode(voucher.read())
            encoded_string = encoded_string.decode('utf-8')

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        }
        payload = json.dumps({
            "b64Content": encoded_string,
            "fileName": file_name,
            "isOverwrite": "false"
        })

        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        print("Ownership Voucher Uploaded: " + file_name)
        return True
    except Exception as e:
        log.error("Upload Ownership Voucher: {} failed!".format(file_name))
        log.debug("Exception {} occurred." .format(e.__class__))

    return False


def check_profile_exists(cw_url, token, profile_name):
    # Check if ZTP profile exists
    url = cw_url + '/crosswork/ztp/v1/profiles/query'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    payload = json.dumps({
        "filter": {
            "profileName": profile_name
        }
    })
    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        if ('ztpProfiles' in response.json()):
            for profile in response.json()['ztpProfiles']:
                if (profile['profileName'] == profile_name):
                    return True
        return False
    except Exception as e:
        log.error("ZTP Profile query failed!")
        log.debug("Exception {} occurred." .format(e.__class__))

    return False

def get_config_uuid_by_name(cw_url, token, config_name):
    # get config uuid by name
    url = cw_url + '/crosswork/configsvc/v1/configs'
    headers = {
        'Authorization': 'Bearer ' + token
    }
    params = {
        'confname': config_name,
    }

    try:
        response = requests.request("GET", url, headers=headers, params=params, verify=False)
        config = response.json()["content"]
        if config:
            config_id = config[0]['confId']
            return config_id
        return False
    except Exception as e:
        log.error("Get config UUID by name failed - {}".format(config_name))
        log.debug("Exception {} occurred." .format(e.__class__))
        log.debug("Request response: {}" .format(response))
        return False


def upload_ztp_config_file(cw_url, token, config_name, os_platform, version, device_family, file, config_type = 'Day0-config'):
    # Upload ztp config file
    url = cw_url + '/crosswork/configsvc/v1/configs/upload'
    headers = {
        'Authorization': 'Bearer ' + token
    }
    params = {
        'confname': config_name,
        'osname': os_platform,
        'version': version,
        'devicefamily': device_family,
        'user': "ZTPScript",
        'type': config_type
    }
    files=[
        ('configFile',open(file,'rb'))
    ]
    
    try:
        response = requests.request("POST", url, headers=headers, files=files, params=params, verify=False)
        if ('confId' in response.json()):
            config_id = response.json()['confId']
            return config_id
        print(response.text)
        return False
    except Exception as e:
        log.error("ZTP Config file upload - {} upload failed!".format(config_name))
        log.debug("Exception {} occurred." .format(e.__class__))
        log.debug("Request response: {}" .format(response))
        return False

def get_imageid_by_title(cw_url, token, image_title):
    # Get image id from crossworks by image title
    url = cw_url + '/crosswork/imagesvc/v1/images'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    params = {
        'imageTitle': image_title
    }

    try:
        response = requests.request("GET", url, headers=headers, params=params, verify=False)
        image = response.json()['content']
        if image:
            image_id = image[0]['id']
            return image_id
        return False
    except Exception as e:
        log.error("Get Image ID by name: {} failed!".format(image_title))
        log.debug("Exception {} occurred." .format(e.__class__))

    return False

def create_ztp_profile(cw_url, token, config, device_family, secure_ztp, os_platform, profile_name, version,
                       post_config = '', pre_config = '', software_image = ''):
    # Create ztp profile
    url = cw_url + '/crosswork/ztp/v1/profiles'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    payload = json.dumps({
    "profiles": [
        {
        "config": config,
        "deviceFamily": device_family,
        "image": software_image,
        "isSecureZtp": secure_ztp,
        "osPlatform": os_platform,
        "postConfig": post_config,
        "preConfig": pre_config,
        "profileCategory": "IOS XR",
        "profileDescription": profile_name,
        "profileName": profile_name,
        "version": version
        }
    ]
    })

    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        print(response.text)
        return response.text
    except Exception as e:
        log.error("Create ZTP Profile: {} failed!".format(profile_name))
        log.debug("Exception {} occurred." .format(e.__class__))

def check_for_ztp_device(cw_url, token, host_name, serial_number):
    # Check for existing ztp device with serial number
    url = cw_url + "/crosswork/ztp/v1/devices/query"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    payload = json.dumps({
        "filter": {
            "serialNumber": [serial_number]
        }
    })
    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        ztp_nodes = ''
        if 'ztpnodes' in response.json():
            ztp_nodes = response.json()['ztpnodes']

            if ztp_nodes:
                for node in ztp_nodes:
                    if serial_number in node['serialNumber']:
                        return node
        return False
    except Exception as e:
        log.error("ZTP Device query failed!")
        log.debug("Exception {} occurred." .format(e.__class__))
        return False

def create_ztp_device_csv(original, output):
    # Create ZTP Device CSV
    try:
        shutil.copyfile(original, output)
    except Exception as e:
        log.error("Create ZTP device CSV: {} failed!".format(output))
        log.debug("Exception {} occurred." .format(e.__class__))

def add_ztp_device_to_csv(writer, os_platform, serial_number, host_name, credential_profile, uuid = '', is_secure_ztp = 'false', 
                      mac_address = '', device_family = '', profile_name = '', software_image = '', config_file = '', status = 'Unprovisioned',
                      provider_name = '', version = '', isis_system_id = '', ospf_router_id = '', te_id ='', config_attributes = {},
                      location_enabled = 'false', ip_address = '', config_mode = '', product_id = '', inventory_id = '',
                      pre_config = '', post_config = '', connectivity_protocol = '', connectivity_ip_address = '', connectivity_port = '', connectivity_timeout = ''):
    # Flatten config_attributes dict into string
    if config_attributes:
        config_str = ','.join("{!s}={!s}".format(key,val) for (key,val) in config_attributes.items())
    else:
        config_str = ''

    # Write device to ZTP Device CSV
    data = [serial_number, location_enabled, '', '', host_name, credential_profile, os_platform, version, device_family, config_file, profile_name,
            product_id, uuid, mac_address, ip_address, config_str, connectivity_protocol, connectivity_ip_address, connectivity_port, connectivity_timeout, provider_name, inventory_id, is_secure_ztp, '', software_image, pre_config,
            post_config, config_mode, '', ospf_router_id, isis_system_id, te_id]

    try:
        writer.writerow(data)
    except Exception as e:
        log.error("Writing ZTP device in CSV: {} failed!".format(host_name))
        log.debug("Exception {} occurred." .format(e.__class__))

def import_devices_csv(cw_url, token, ztp_devices_csv):
    # import ZTP devices CSV to CNC
    url = cw_url + '/crosswork/ztp/v1/devices/import'

    try:
        with open(ztp_devices_csv, "rb") as voucher:
            # base 64 encoding of the csv for payload
            encoded_string = base64.b64encode(voucher.read())
            encoded_string = encoded_string.decode('utf-8')

        print(encoded_string)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        }
        payload = json.dumps({
            "b64Content": encoded_string,
            "isDryRun": False
        })

        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        if response.json()['code'] == 200:
            print(str(response.json()['code']) + ": ZTP Devices Created in CNC")
        elif "message" in response.json():
            print(response.json()['message'])
        else:
            print(response.text)
    except Exception as e:
        log.error("Failed to Import Devices CSV: {}".format(ztp_devices_csv))
        log.debug("Exception {} occurred." .format(e.__class__))

def create_ztp_device(cw_url, token, os_platform, serial_number, host_name, credential_profile, uuid = '', is_secure_ztp = 'false', 
                      mac_address = '', device_family = '', profile_name = '', software_image = '', config_file = '', status = 'Unprovisioned',
                      provider_name = '', version = '', isis_system_id = '', ospf_router_id = '', te_id ='', config_attributes = {},
                      location_enabled = 'false', ipaddrs = '', mask = 0, config_mode = ''):
    # Creates a ZTP device into CNC
    url = cw_url + "/crosswork/ztp/v1/devices"
    payload = json.dumps({
    "nodes": [{
        "uuid": uuid,
        "hostName": host_name,
        "serialNumber": [
            serial_number
        ],
        "isSecureZtp": is_secure_ztp,
        "macAddress": mac_address,
        "ipAddress": {
            "ipaddrs": ipaddrs,
            "mask": mask
        },
        "credentialProfile": credential_profile,
        "osPlatform": os_platform,
        "deviceFamily": device_family,
        "profileName": profile_name,
        "image": software_image,
        "config": config_file,
        "status": status,
        "providerInfo": {
            "providerName": provider_name
        },
        "version": version,
        "additionalAttributes": {
            "routingInfo.globalisissystemid": isis_system_id, 
            "routingInfo.globalospfrouterid": ospf_router_id, 
            "routingInfo.teRouterid": te_id
        },
        "configAttributes": config_attributes,
        "connectivityDetails": [],
        "enableOption82": location_enabled,
        "secureZtpInfo": {
            "configMode": config_mode
        }
    }]
    })
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
    }

    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        print(response.text)
        
    except Exception as e:
        log.error("Create ZTP Device: {} failed!".format(host_name))
        log.debug("Exception {} occurred." .format(e.__class__))

    return response.text

def clean_hostname(host_name):
    result = host_name.strip()
    result = result.replace('-' and '_', ' ')
    result = re.sub('[^ A-Za-z0-9]+', '', result)
    result = ' '.join(result.split())
    result = result.replace(' ', '-')

    return result

def check_ipv4_address(ipv4_address, mask = 0):

    if not(re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",ipv4_address)):
        return False

    if not(0 <= mask <= 32):
        return False
    
    return True

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == "":
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' " "(or 'y' or 'n').\n")

def create_net_id(area_code, loopback_ip):
    # Generate NET_ID with 49.<Areacode>.<loopback IP>.00
    ip_filled = ''
    loopback_ip_split = loopback_ip.split('.')
    for i in loopback_ip_split:
        ip_filled = ip_filled + i.zfill(3)
    net_id_ip = '.'.join(list(map(''.join, zip(*[iter(ip_filled)]*4))))
    net_id_area = str(area_code).strip().zfill(4)
    net_id = "49.{net_id_area}.{net_id_ip}.00".format(net_id_area = net_id_area, net_id_ip = net_id_ip)
    return net_id

def dhcp_create_client(payload, rest_url=None):
    if rest_url is not None:
       url = CPNR_URL + rest_url
    else:
       url = CPNR_URL + "/web-services/rest/resource/ClientEntry"

    headers = {
        'Authorization': 'Basic YWRtaW46Y2lzY28hMTIz',
        'Content-Type': 'application/xml'
    }
    print(payload)

    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify = False)
        print(response.text)
        return True
    except Exception as e:
        log.error("Create DHCP Client Entry Failed")
        log.debug("Exception {} occurred." .format(e.__class__))
        return False

def dhcp_reload_server():
    url = CPNR_URL + "/web-services/rest/resource/DHCPServer"

    params = {
        "action": 'reloadServer'
    }
    payload = ""
    headers = {
    'Authorization': 'Basic YWRtaW46Y2lzY28hMTIz'
    }

    try:
        response = requests.request("PUT", url, headers=headers, data=payload, params=params, verify = False)
        print(response.text)
        return True
    except Exception as e:
        log.error("DHCP server reload Failed")
        log.debug("Exception {} occurred." .format(e.__class__))
        return False


def enable_dhcp_entries(cw_url, cw_token, devices_dict):
    # Post DHCP client entries to cpnr
    
    print("Enabling DHCP for batch: " + args.batch)
    for device in devices_dict:
        serial_number = device['Serial Number']
        image = get_imageid_by_title(cw_url, cw_token, env['image_name'])
        if not image: continue
        config_name = ZTP_SCRIPT
        config = get_config_uuid_by_name(cw_url, cw_token, config_name)
        if not config: continue
        
        ### iso image location 
        payloads = []
        reservation_payloads = []
        payloads.append("""<ClientEntry xmlns=\"http://ws.cnr.cisco.com/xsd\">
            <domainName>nbnzone.com</domainName>
            <embeddedPolicy>
                <name>client-policy:{serial_number}-iso</name>
                <packetFileName>http://192.168.131.233:30604/crosswork/imagesvc/v1/device/files/{image}</packetFileName>
            </embeddedPolicy>
            <hostName>{host_name}</hostName>
            <name>{serial_number}-iso</name>
            <tenantId>0</tenantId>
        </ClientEntry>""".format(serial_number = serial_number, host_name = device['Host_Name'], image = image))

        # iso ipxe
        payloads.append("""<ClientEntry xmlns=\"http://ws.cnr.cisco.com/xsd\">\r
            <domainName>nbnzone.com</domainName>\r
            <embeddedPolicy>\r
                <name>client-policy:{serial_number}-iso-ipxe</name>\r
                <packetFileName>http://192.168.131.233:30604/crosswork/imagesvc/v1/device/files/{image}</packetFileName>\r
            </embeddedPolicy>\r
            <hostName>{host_name}</hostName>\r
            <name>{serial_number}-iso-ipxe</name>\r
            <tenantId>0</tenantId>\r
        </ClientEntry>""".format(serial_number = serial_number, host_name = device['Host_Name'], image = image))

        # config script
        payloads.append("""<ClientEntry xmlns=\"http://ws.cnr.cisco.com/xsd\">\r
            <domainName>nbnzone.com</domainName>\r
            <embeddedPolicy>\r
                <name>client-policy:{serial_number}-script</name>\r
                <packetFileName>http://192.168.131.233:30604/crosswork/configsvc/v1/configs/device/files/{config}</packetFileName>\r
                <vendorOptions>\r
                    <OptionItem>\r
                        <number>43</number>\r
                        <optionDefinitionSetName>Cisco-ZTP</optionDefinitionSetName>\r
                        <value>(clientId 1 xr-config)(authCode 2 0)</value>\r
                    </OptionItem>\r
                </vendorOptions>\r
            </embeddedPolicy>\r
            <hostName>{host_name}</hostName>\r
            <name>{serial_number}-script</name>\r
            <tenantId>0</tenantId>\r
        </ClientEntry>""".format(serial_number = serial_number, host_name = device['Host_Name'], config = config))

        # config exr-script
        payloads.append("""<ClientEntry xmlns=\"http://ws.cnr.cisco.com/xsd\">\r
            <domainName>nbnzone.com</domainName>\r
            <embeddedPolicy>\r
                <name>client-policy:{serial_number}-exrscript</name>\r
                <packetFileName>http://192.168.131.233:30604/crosswork/configsvc/v1/configs/device/files/{config}</packetFileName>\r
                <vendorOptions>\r
                    <OptionItem>\r
                        <number>43</number>\r
                        <optionDefinitionSetName>Cisco-ZTP</optionDefinitionSetName>\r
                        <value>(clientId 1 exr-config)(authCode 2 0)</value>\r
                    </OptionItem>\r
                </vendorOptions>\r
            </embeddedPolicy>\r
            <hostName>{host_name}</hostName>\r
            <name>{serial_number}-exrscript</name>\r
            <tenantId>0</tenantId>\r
        </ClientEntry>""".format(serial_number = serial_number, host_name = device['Host_Name'], config = config))

        # Reservation payloads
        reservation_payloads.append("""<Reservation xmlns=\"http://ws.cnr.cisco.com/xsd\">\r
            <ipaddr>{ip_address}</ipaddr>\r
            <lookupKey>{serial_number}</lookupKey>\r
            <deviceName>{host_name}</deviceName>\r
            <lookupKeyType>7</lookupKeyType>\r
        </Reservation>""".format(ip_address = device['SWR_DHCP_IPADDRR'], serial_number = serial_number.encode('utf-8').hex(), host_name = device['Host_Name']))

        
        for payload in payloads:
            dhcp_create_client(payload)
        
        for payload in reservation_payloads:
            dhcp_create_client(payload, rest_url="/web-services/rest/resource/Reservation")

    dhcp_reload_server()


def show_ztp_process(env, cw_url, cw_token, devices_dict):
    # Show ZTP Device turn-up process in setps
    config_template_loc = env['config_template_file']
    create_devices = True

    # Print the files and batch id used.
    print("\nShow ZTP Device Turn-Up process")
    print("\nConfig file Template: " + config_template_loc)
    print("Devices CSV: " + env['device_file'])
    print("Devices batch id: " + str(args.batch))
    print("ZTP Profile creation: " + str(args.use_profiles))
    
    # Check software image exists in CNC. If software image is not found then ZTP Device turn-up process cannot be run.
    software_image = get_imageid_by_title(cw_url, cw_token, env['image_name'])
    if (software_image == False):
        print("\nSoftware Image with name {} not found. The ZTP Device Turn-Up process cannot be run.".format(env['image_name']))
        print("Please check for software image in CNC and ensure the Software Image name matches in the env file.")
        return False

    print("\n-------------------------------------------------------------------------")
    
    for device in devices_dict:
        # For each device in the devices CSV file
        host_name = clean_hostname(device['Host_Name'])
        print("\nDevice: " + host_name)
        print("Serial Number: " + device['Serial Number'])

        # Check if Device exists - this device will not be created in the ZTP Device Turn-Up process.
        ztp_device = check_for_ztp_device(cw_url, cw_token, host_name, device['Serial Number'])
        if (ztp_device):
            if ztp_device['status'] == 'Unprovisioned':
                print("\nZTP Device will be updated - ZTP Device with Serial Number already exists with UUID: " + str(ztp_device['uuid']))
                print("\n-------------------------------------------------------------------------")
            else:
                print("\nZTP Device will not be created - ZTP Device with serial number already exists with UUID: {} \nDevice status: {}".format(str(ztp_device['uuid']), ztp_device['status']))
                print("\n-------------------------------------------------------------------------")
            create_devices = False
            continue

        # Check device serial number
        serial_query = check_serial_number(cw_url, cw_token, device['Serial Number'])
        if not(serial_query): # If serial number doesn't exist
            if (env['is_secure_ztp'] == 'true'): # If secure ztp
                file_name = device['Serial Number'] + '.vcj'
                voucher_loc = env['vouchers_folder'] + file_name
                if exists(voucher_loc):
                    print("Voucher upload to be uploaded: " + voucher_loc)
            else:
                print("Serial Number to be added: " + device['Serial Number'])
        elif (serial_query['isOVLinked'] == 'false' and env['is_secure_ztp'] == 'true'): # serial number exists and no OV for secure ztp
            file_name = device['Serial Number'] + '.vcj'
            voucher_loc = env['vouchers_folder'] + file_name
            if exists(voucher_loc):
                print("Voucher upload to be uploaded: " + voucher_loc)
        
        # Check the Profile to be created
        if (args.use_profiles == True):
            profile_name = host_name + '-profile'
            if(check_profile_exists(cw_url, cw_token, profile_name)):
                print("\nZTP Profile with name {} exists.".format(profile_name))
                print("Device {host_name} will be created with the {profile} profile.".format(host_name=host_name, profile=profile_name))
            continue
        
        # Check for config file
        config_name = host_name + '-config'
        config = get_config_uuid_by_name(cw_url, cw_token, config_name)
        if not(config):
            file_loc = './config-files/' + config_name + '.txt' # location of file to be created './conf-files/'hostname'-config.txt'
            if exists(file_loc):
                print('Config File to be overwritten: ' + file_loc)
            else: print('Config File to be created: ' + file_loc)
            print("Config File to be uploaded: " + file_loc)
        
        if (args.use_profiles == True):
            print("Profile to be created: " + profile_name)

        print("\n-------------------------------------------------------------------------")

    return create_devices

def ztp_devce_turnup(env, cw_url, cw_token, devices_dict):
    config_template_loc = env['config_template_file']

    print("\nZTP Device Turn-Up main process")

    # Get software image
    software_image = get_imageid_by_title(cw_url, cw_token, env['image_name'])
    if (software_image == False):
        print("\nSoftware Image with name {} not found. The ZTP Device Turn-Up process cannot be run.".format(env['image_name']))
        print("Please check for software image in CNC and ensure the Software Image name matches in the env file.")
        return

    # Read config template file as Jinja2 template
    with open(config_template_loc, 'r') as f:
        # template = f.read()
        template = jinja2.Template(f.read())

    # Create ZTP Device CSV file 
    original = './files/ztpDeviceManagement.csv'
    output = './output/' + args.batch + '.csv'
    create_ztp_device_csv(original, output)

    # Device creation variables
    device_version = ''
    device_device_family = ''
    device_software_image = ''
    
    if (args.use_profiles == False):
        device_version = env['device_version']
        device_device_family = env['device_family']
        device_software_image = software_image
        

    # For each device create config file, upload file, create profile and create device
    for device in devices_dict:
        host_name = clean_hostname(device['Host_Name'])
        profile_name = host_name + '-profile'
        config_name = host_name + '-config'
        is_secure_ztp = env['is_secure_ztp']
        os_platform = env['device_OS']
        version = env['device_version']
        device_family = env['device_family']
        device['NET_ID'] = create_net_id(device['Area Code'], device['SWR_LOOPBACK0_IPADDRR'])
        #Deriving L0_SRINDEX from loopback 0
        device['L0_SRINDEX'] = device['SWR_LOOPBACK0_IPADDRR'].split(".")[-1]

        # check for serial number, if not already in list, add to list
        serial_query = check_serial_number(cw_url, cw_token, device['Serial Number'])
        if not(serial_query): # If serial number doesn't exist
            if (is_secure_ztp == 'true'): # Add OV if secure ztp
                file_name = device['Serial Number'] + '.vcj'
                if not(add_ownership_voucher(cw_url, cw_token, file_name, env['vouchers_folder'])):
                    print("Failed Uploading ownership voucher")
                    continue
            else:
                if not(add_serial_number(cw_url, cw_token, device['Serial Number'])):
                    print("Failed adding serial number")
                    continue
        elif (serial_query['isOVLinked'] == 'false' and is_secure_ztp == 'true'): # serial number exists and no OV for secure ztp
                file_name = device['Serial Number'] + '.vcj'
                if not(add_ownership_voucher(cw_url, cw_token, file_name, env['vouchers_folder'])):
                    print("Failed Uploading ownership voucher")
                    continue            

        # create config file
        config = get_config_uuid_by_name(cw_url, cw_token, config_name)
        if not(config):
            file_loc = './config-files/' + config_name + '.txt' # location of file to be created './conf-files/'hostname'-config.txt'
            if not create_config_from_template(file_loc, template, device):
                print("\nDevices turn-up failed on device: " + device['Host_Name'])
                return False

            # upload ztp config file
            config = upload_ztp_config_file(cw_url, cw_token, config_name, os_platform, version, device_family, file_loc)
            if not config:
                print("\nDevices turn-up failed on device: " + device['Host_Name'])
                return


        # create profile if profile doesn't exist and use profiles is true
        if (not(check_profile_exists(cw_url, cw_token, profile_name)) and args.use_profiles):
            create_ztp_profile(cw_url, cw_token, config, device_family, is_secure_ztp, os_platform, profile_name, version, software_image = software_image)

        # create ztp device
        os_platform = env['device_OS']
        serial_number = device['Serial Number']
        credential_profile = env['credential_profile']
        provider_name = env['provider_name']
        device_profile = ''
        device_config = config

        # Configuration Attributes to be added for device - to do - make easily configurable
        config_attributes = {
            "DESIRED_VER": env['device_version'],
            "CROSSWORK_VIP": CROSSWORK_VIP,
            "CROSSWORK_PORT": CROSSWORK_PORT,
            "CW_CONFIG_UUID": config,
            "CW_IMAGE_UUID": software_image,
            "LABEL": device['Label'],
            "INTERFACE": device['MPLS_NNI_PORT_ID1'],
            "VRF": device['VRF'],
            "TOKEN": device['Token'],
            "EPNM_IP": EPNM_IP,
            "EPNM_USERNAME": EPNM_USERNAME,
            "EPNM_PASSWORD": EPNM_PASSWORD,
            "EPNM_CRED_POLICY": EPNM_CRED_POLICY,
            "LOOPBACK1_ADDRESS": device['SWR_LOOPBACK1_IPADDRR']
        }

        ip_address = device['SWR_DHCP_IPADDRR'].strip()

        

        # If profiles requested then populate required info in device
        if (args.use_profiles == True):
            device_config = config
            device_profile = profile_name

        # secure ZTP set config mode to overwrite
        if (is_secure_ztp == 'true'):
            config_mode = 'overwrite'
        else:
            config_mode = ''

        # check IPv4 address and mask is correct format
        if (device['SWR_DHCP_IPADDRR']):
            if (check_ipv4_address(device['SWR_DHCP_IPADDRR'])):
                ipaddrs = device['SWR_DHCP_IPADDRR']
                ip_address = ipaddrs + '/27'
            else:
                ip_address = ''

        # Write to devices csv in output file
        with open(output, 'a') as ztp_devices_csv:
            ztp_devices_csv_writer = csv.writer(ztp_devices_csv)
            loopback1_add = device['SWR_LOOPBACK1_IPADDRR'].strip() + "/32"
            connectivity_protocol = "SSH"
            connectivity_ip_address = loopback1_add
            connectivity_port = "22"
            connectivity_timeout = "120"

            add_ztp_device_to_csv(ztp_devices_csv_writer, os_platform, serial_number, host_name, credential_profile, is_secure_ztp = is_secure_ztp, 
                            profile_name = device_profile, ip_address = ip_address, provider_name = provider_name, version = device_version,
                            device_family = device_device_family, software_image = device_software_image, config_file = device_config, config_mode = config_mode, 
                            connectivity_protocol = connectivity_protocol, connectivity_ip_address = connectivity_ip_address, connectivity_port = connectivity_port,
                            connectivity_timeout = connectivity_timeout, config_attributes = config_attributes)
            ztp_devices_csv.close()
            
        # Create Groups and Tags for device - todo


    # Create device if device creation selected
    if (args.device_creation):
        import_devices_csv(cw_url, cw_token, output)


def main(env, devices_dict):

    cw_url = "{protocol}://{host}:{port}".format(protocol=env['protocol'],host=env['host'],port=env['port'])

    # generate crossworks api token
    cw_ticket = generate_ticket(cw_url, env['cw_user'], env['cw_pass'])

    if (cw_ticket):   
        cw_token = generate_token(cw_url, cw_ticket)
        continue_create = True
        
        if (args.enable):
            enable_dhcp_entries(cw_url, cw_token, devices_dict)
        else:
            if (args.show_process):
                continue_create = show_ztp_process(env, cw_url, cw_token, devices_dict)

                if (continue_create and args.create):
                    continue_create = query_yes_no("\nWould you like to continue device creation?")
                    if not continue_create:
                        print("Device creation cancelled")

            if (args.create and continue_create):
                ztp_devce_turnup(env, cw_url, cw_token, devices_dict)

        # Create DHCP entries in CPNR for batch
        if (args.enable):
            return


if __name__ == '__main__':
    
    env = read_env_properties(ENV_FILE, ENV_PROFILE) # Read static variables from profiles.json
    if (env):
        devices_file_loc = env['device_file']

        # Load device details from excel to dictionary query by batch ID
        devices_csv = read_csv(devices_file_loc, keep_default_na=False, chunksize=10000)
        devices_dict = concat((x.query("Batch == '{}'".format(args.batch)) for x in devices_csv), ignore_index=True).to_dict(orient='records')

        if devices_dict:
            # verify_devices_input(devices_dict)
            main(env, devices_dict)
        else:
            log.error("Batch ID error - No Devices with batch ID: " + args.batch)