import argparse
import json
import requests
import socket
import sys
from pprint import pprint
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

######### Denon Input Assignments ##############
# Denon Name   = Label   = Input    = Command
# ----------------------------------------------
# CBL/SAT      = TiVo    = HDMI-1   = SISAT/CBL
# Blu-ray      = Plex    = HDMI-3   = SIBD
# Game         = PS4     = HDMI-4   = SIGAME
# Media Player = AppleTV = HDMI-5   = SIMPLAY
# CD           = Vinyl   = Analog 5 = SICD
################################################

# map inputs and picture settings per device
input_map = {
    'AppleTV': {'tv_input': 'HDMI-2', 'picture_mode': 'GeekSquad', 'denon_cmd': 'SIMPLAY'},
    'TiVo': {'tv_input': 'HDMI-2', 'picture_mode': 'GeekSquad', 'denon_cmd': 'SISAT/CBL'},
    'PS4': {'tv_input': 'HDMI-2', 'picture_mode': 'PS4', 'denon_cmd': 'SIGAME'},
    'Plex': {'tv_input': 'HDMI-2', 'picture_mode': 'GeekSquad', 'denon_cmd': 'SIBD'},
    'Vinyl': {'tv_input': None, 'picture_mode': None, 'denon_cmd': 'SICD'},
    'Network': {'tv_input': None, 'picture_mode': None, 'denon_cmd': 'SINET'}
}

denon_ip = '192.168.1.116'
vizio_ip = '192.168.1.50'
vizio_key = 'foo' # see https://github.com/exiva/Vizio_SmartCast_API for pairing info to get a key


def parse_args():
    """Parse command line arguments."""
    epilog = "something clever"
    parser = argparse.ArgumentParser(epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", nargs="?", default="off",
                        choices=['AppleTV', 'TiVo', 'PS4', 'Plex', 'Vinyl', 'Network', 'off'],
                        help="command to send to HEOS player")
    parser.add_argument("-r", '--report', nargs='?', default=False)
    return parser.parse_args()


def vizio_api(path, json={}, put=False):
    ''' all your vizio api requests handled at one low price '''
    headers = {'AUTH': vizio_key}
    url = 'https://{}:7345/{}'.format(vizio_ip, path)
    if put:
        result = requests.put(url=url, headers=headers, verify=False, json=json)
    else:
        result = requests.get(url=url, headers=headers, verify=False).json()
    return result


def denon_api(command, return_match, debug=False):
    ''' Denon was so lasy for an API, they just opened up their RS232 protocol over port 23 on the network
     ...at least it's there and it works. '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((denon_ip, 23))
    s.sendall("{}\n".format(command).encode())
    while True:
        data = s.recv(135).split('\r'.encode()) # denon spec says 135 bytes max
        for line in data:
            if debug:
                print("Received: {}".format(line.decode()))
            if line.strip().startswith(return_match.encode()):
                s.shutdown(socket.SHUT_WR)
                s.close()
                return(line.decode())
    s.shutdown(socket.SHUT_WR)
    s.close()
    return "Connection closed."


def power_off():
    ''' this is here so home assistant can power off both devices at once '''
    denon_power = denon_api(command="PW?", return_match='PW')
    if denon_power != "PWSTANDBY":
        denon_api(command="PWSTANDBY", return_match='PW')
    json = {"KEYLIST": [{"CODESET": 11,"CODE": 0,"ACTION":"KEYPRESS"}]}
    vizio_api(path="key_command/", json=json, put=True)
    sys.exit()


def main():
    '''here we go! based on the input_map, coordinate A/V settings between the TV and the Denon'''

    # track if this thing already setup correctly
    state_matches = True

    # figure out WTF to do
    script_args = parse_args()
    requested_input = script_args.input
    if requested_input == "off":
        power_off()

    # make sure the Dennon is on, because duh
    denon_power = denon_api(command="PW?", return_match='PW')
    if denon_power != "PWON":
        state_matches = False
        if not script_args.report:
            denon_api(command="PWON", return_match='PW')

    # set Denon to requested input like magic
    denon_input = denon_api(command="SI?", return_match='SI')
    if denon_input != input_map[requested_input]['denon_cmd']:
        state_matches = False
        if not script_args.report:
            # only set Denon to requested input if it's different, or it hangs
            denon_api(command=input_map[requested_input]['denon_cmd'], return_match='SI')

    # moving onto the TV...
    if input_map[requested_input]['picture_mode'] is not None:
        # get info for current pic mode
        vizio_modes = vizio_api(path="menu_native/dynamic/tv_settings/picture/picture_mode")
        vizio_mode_hash = vizio_modes['ITEMS'][0]['HASHVAL']
        vizio_mode_name = vizio_modes['ITEMS'][0]['VALUE']
        
        # based on the map, set the picture mode to be sexy for video or fast for gaming
        if input_map[requested_input]['picture_mode'] != vizio_mode_name:
            state_matches = False
            if not script_args.report:
                json = {
                    "REQUEST": "MODIFY", 
                    "HASHVAL": vizio_mode_hash, 
                    "VALUE": input_map[requested_input]['picture_mode']
                    }
                vizio_api(path="menu_native/dynamic/tv_settings/picture/picture_mode", json=json, put=True).json()

    if input_map[requested_input]['tv_input'] is not None:
        # turn TV on if needed
        vizio_power = vizio_api(path="state/device/power_mode")['ITEMS'][0]['VALUE']
        if vizio_power != 1:
            state_matches = False
            if not script_args.report:
                json = {"KEYLIST": [{"CODESET": 11,"CODE": 1,"ACTION":"KEYPRESS"}]}
                vizio_api(path="key_command/", json=json, put=True)

        # get hash for current video input (don't smoke it)
        vizio_inputs = vizio_api(path="menu_native/dynamic/tv_settings/devices")
        # find vizio's current input hash in dictionary
        for item in vizio_inputs['ITEMS']:
            if item['CNAME'] == "current_input":
                vizio_input_hash = item['HASHVAL']
                vizio_input_name = item['VALUE']
                break
        if vizio_input_name != input_map[requested_input]['tv_input']:
            state_matches = False
            if not script_args.report:
                json = {
                    "REQUEST": "MODIFY", 
                    "HASHVAL": vizio_input_hash,
                    "VALUE": input_map[requested_input]['tv_input']
                    }
                # set vizio's video input
                vizio_api(path="menu_native/dynamic/tv_settings/devices/current_input", json=json, put=True).json()
    if script_args.report:
        if state_matches:
            sys.exit(0) 
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
