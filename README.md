# CNC - ZTP Device setup 

The Crossworks Network Controller (CNC) - Zero Touch Provision (ZTP) Device setup script performs these actions from a set of devices in a CSV file:
- Adds device serials and vouchers into CNC
- Creates and uploads the ZTP day0-config file from a template file
- Creates ZTP Profiles (Optional)
- Creates a CSV of ZTP devices to import into CNC
- Adds ZTP devices into CNC (Optional)

## Getting Started

This script was written in Python 3.10.x. The recommended python version will be Python 3.10.x for the execution of this script.

### Prerequisites

This script uses third-party libraries. You must install those prior to executing this script, which you can do with the following command:

```pip install -r requirements.txt``` 

## Usage

1. Make a copy of files/devices/devices_template.csv and fill in the ZTP devices required to create in CNC

*Note: Batch ID is required*


2. Add a ZTP config file template in the files/templates folder

*Note: The variables in the template file will be replaced using Jinja2, variable names will need to be formatted as {{variable}}. Variable names will need to match the devices CSV file.*

3. Make a copy of env/profiles_template.json file and fill in with your required information. Change lines in the ztp-device-setup.py to match the env file. (Line 27/28)
    ```
    ENV_FILE = ""
    ENV_PROFILE = ""
    ```

*Note: "is_secure_ztp" input is either 'true' or 'false'. Vouchers are required if 'true'*

4. Change ztp-device-setup.py line 29 to CPNR URL (https://{host}:{port})
    ```
    CPNR_URL = ""
    ```
5. Running the script:
    - ```python ztp-device-setup.py -batch batch_id``` - Show the process for devices with the batch id
    - ```python ztp-device-setup.py -batch batch_id --create``` - Show the process and prompts if you would like to create the ztp devices. This will upload serial numbers and config files then add the information to the output/batchid.csv file.
    - ```python ztp-device-setup.py -batch batch_id --enable``` - This will post the serial number/host name with the relevant ISO image and ZTP script to CPNR (Update line 29 in ztp-device-setup.py if the ztp script name changes in CNC)
6. To upload devices to CNC, use the CNC UI
    1. Go into Device Management -> Network Devices -> Zero Touch Devices
    2. Import Unprovisioned Devices 
    3. Look for the output/ folder and select the batchid.csv with the batch id to be uploaded.

*Notes:*
1. *device will not be created if the serial number is already used in CNC.*
2. *config file will not be generated if config with name 'devicename-config' already exists in CNC*
3. *output file will be overwritten if it contains the same batch id*

## Authors

- Christopher Yip (chryip@cisco.com)
