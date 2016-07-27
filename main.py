#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import json
import multiprocessing
import os
import re
import struct
import time
from datetime import datetime
from multiprocessing.pool import ThreadPool
from gpsoauth import perform_master_login, perform_oauth

import requests
from geopy.geocoders import GoogleV3
from google.protobuf.internal import encoder

import pokemon_pb2

ADDRESS_KEY = 'address'

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    pass
from s2sphere import *


def encode(cellid):
    output = []
    encoder._VarintEncoder()(output.append, cellid)
    return ''.join(output)


def get_neighbors(scan_location):
    origin_cell = CellId.from_lat_lng(LatLng.from_degrees(scan_location[LAT_KEY], scan_location[LONG_KEY])).parent(15)
    walk = [origin_cell.id()]
    # 10 before and 10 after
    next_cell = origin_cell.next()
    prev = origin_cell.prev()
    for i in range(10):
        walk.append(prev.id())
        walk.append(next_cell.id())
        next_cell = next_cell.next()
        prev = prev.prev()
    return walk


with open('config.json') as config_file:
    credentials = json.load(config_file)

AUTH_TYPE_KEY = 'AUTHTYPE'
PASSWORD_KEY = 'PASSWORD'
USER_NAME_KEY = 'USERNAME'
LOCATION_KEY = 'LOCATION'
ALT_KEY = 'alt'
LONG_KEY = 'lng'
LAT_KEY = 'lat'
BIN_ALT_KEY = 'bin_alt'
BIN_LONG_KEY = 'bin_lng'
BIN_LAT_KEY = 'bin_lat'
GYM_KEY = 'gym'
POKESTOP_KEY = 'pokestop'

PTC_CLIENT_SECRET = credentials.get('PTC_CLIENT_SECRET', None)
ANDROID_ID = credentials.get('ANDROID_ID', None)
SERVICE = credentials.get('SERVICE', None)
CLIENT_SIG = credentials.get('CLIENT_SIG', None)
GMAPS_API_KEY = credentials.get('GOOGLE_MAPS_API_KEY', None)

DEFAULT_API_URL = 'https://pgorelease.nianticlabs.com/plfe/rpc'
LOGIN_URL = 'https://sso.pokemon.com/sso/login?service=https%3A%2F%2Fsso.pokemon.com%2Fsso%2Foauth2.0%2FcallbackAuthorize'
LOGIN_OAUTH = 'https://sso.pokemon.com/sso/oauth2.0/accessToken'

DEFAULT_MAX_LOGIN_RETRIES = 5
DEFAULT_API_ENDPOINT_RETRIES = 5

is_valid = {}

DEBUG = False
default_step = 0.001

poke_data_lock = multiprocessing.Lock()
poke_data = {
    'pokemon': {},
    'pokestop': {},
    'gym': {}
}
pokemons = []

# { 'user_name' : { lat, lng, bin_lat, bin_lng, bin_alt }
user_scan_locations = {}

user_poke_data = []

NUM_STEPS = 10
PKMN_DATA_FILE = os.path.join('web', 'pkmn.json')
PKSTOP_DATA_FILE = os.path.join('web', 'pkstop.json')
GYM_DATA_FILE = os.path.join('web', 'gym.json')
GMAP_DATA_FILE = os.path.join('web', 'gmap.json')

REFRESH_TIME = 1200

DEFAULT_USERS_FILE = 'users.json'

def f2i(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def f2h(x):
    return hex(struct.unpack('<Q', struct.pack('<d', x))[0])


def h2f(x):
    return struct.unpack('<d', struct.pack('<Q', int(x, 16)))[0]


def prune():
    poke_data_lock.acquire()
    # prune despawned pokemon
    try:
        cur_time = int(time.time())
        for (pokehash, poke) in poke_data['pokemon'].items():
            poke['timeleft'] = poke['timeleft'] - (cur_time - poke['timestamp'])
            poke['timestamp'] = cur_time
            if poke['timeleft'] <= 0:
                del poke_data['pokemon'][pokehash]
    finally:
        poke_data_lock.release()


def write_data_to_file():
    poke_data_lock.acquire()
    try:
        # different file for bandwidth save
        with open(PKMN_DATA_FILE, 'w') as f:
            json.dump(poke_data['pokemon'], f, indent=2)

        with open(PKSTOP_DATA_FILE, 'w') as f:
            json.dump(poke_data['pokestop'], f, indent=2)

        with open(GYM_DATA_FILE, 'w') as f:
            json.dump(poke_data['gym'], f, indent=2)
    finally:
        poke_data_lock.release()


def add_pokemon(poke_id, name, lat, lng, timestamp, timeleft):
    poke_data_lock.acquire()
    try:
        pokehash = '%s:%s:%s' % (lat, lng, poke_id)
        if pokehash in poke_data['pokemon']:
            if abs(poke_data['pokemon'][pokehash]['timeleft'] - timeleft) < 2:
                # Assume it's the same one and average the expiry time
                poke_data['pokemon'][pokehash]['timeleft'] += timeleft
                poke_data['pokemon'][pokehash]['timeleft'] /= 2
            else:
                print('[-] Two %s at the same location (%s,%s)' % (name, lat, lng))
                poke_data['pokemon'][pokehash]['timeleft'] = min(poke_data['pokemon'][pokehash]['timeleft'], timeleft)
        else:
            poke_data['pokemon'][pokehash] = {
                'id': poke_id,
                'name': name,
                LAT_KEY: lat,
                LONG_KEY: lng,
                'timestamp': timestamp,
                'timeleft': timeleft
            }
    finally:
        poke_data_lock.release()



def add_pokestop(pokestop_id, lat, lng, timeleft):
    poke_data_lock.acquire()
    try:
        if pokestop_id in poke_data[('%s' % POKESTOP_KEY)]:
            poke_data[POKESTOP_KEY][pokestop_id]['timeleft'] = timeleft
        else:
            poke_data[POKESTOP_KEY][pokestop_id] = {
                'id': pokestop_id,
                LAT_KEY: lat,
                LONG_KEY: lng,
                'timeleft': timeleft
            }
    finally:
        poke_data_lock.release()


def add_gym(gym_id, team, lat, lng, points, pokemon_guard):
    poke_data_lock.acquire()
    try:
        if gym_id in poke_data[GYM_KEY]:
            poke_data[GYM_KEY][gym_id]['team'] = team
            poke_data[GYM_KEY][gym_id]['points'] = points
            poke_data[GYM_KEY][gym_id]['guard'] = pokemon_guard
        else:
            poke_data[GYM_KEY][gym_id] = {
                'id': gym_id,
                'team': team,
                LAT_KEY: lat,
                LONG_KEY: lng,
                'points': points,
                'guard': pokemon_guard
            }
    finally:
        poke_data_lock.release()


def api_req(auth_type, api_endpoint, access_token, scan_location, *mehs, **kw):
    while True:
        try:
            p_req = pokemon_pb2.RequestEnvelop()
            p_req.rpc_id = 1469378659230941192

            p_req.unknown1 = 2

            p_req.latitude = scan_location[BIN_LAT_KEY]
            p_req.longitude = scan_location[BIN_LONG_KEY]
            p_req.altitude = scan_location[BIN_ALT_KEY]

            p_req.unknown12 = 989

            if 'useauth' not in kw or not kw['useauth']:
                p_req.auth.provider = auth_type
                p_req.auth.token.contents = access_token
                p_req.auth.token.unknown13 = 14
            else:
                p_req.unknown11.unknown71 = kw['useauth'].unknown71
                p_req.unknown11.unknown72 = kw['useauth'].unknown72
                p_req.unknown11.unknown73 = kw['useauth'].unknown73

            for meh in mehs:
                p_req.MergeFrom(meh)

            protobuf = p_req.SerializeToString()

            session = requests.session()
            session.headers.update({'User-Agent': 'Niantic App'})
            session.verify = False

            r = session.post(api_endpoint, data=protobuf, verify=False)

            p_ret = pokemon_pb2.ResponseEnvelop()
            p_ret.ParseFromString(r.content)

            if DEBUG:
                print("REQUEST:")
                print(p_req)
                print("Response:")
                print(p_ret)
                print("\n\n")

            if DEBUG:
                print("[ ] Sleeping for 1 second")
            time.sleep(0.51)
            return p_ret
        except Exception, e:
            if DEBUG:
                print(e)
            print('[-] API request error, retrying')
            time.sleep(0.51)
            continue


def get_profile(auth_type, access_token, api, use_auth, scan_location, *reqq):
    req = pokemon_pb2.RequestEnvelop()

    req1 = req.requests.add()
    req1.type = 2
    if len(reqq) >= 1:
        req1.MergeFrom(reqq[0])

    req2 = req.requests.add()
    req2.type = 126
    if len(reqq) >= 2:
        req2.MergeFrom(reqq[1])

    req3 = req.requests.add()
    req3.type = 4
    if len(reqq) >= 3:
        req3.MergeFrom(reqq[2])

    req4 = req.requests.add()
    req4.type = 129
    if len(reqq) >= 4:
        req4.MergeFrom(reqq[3])

    req5 = req.requests.add()
    req5.type = 5
    if len(reqq) >= 5:
        req5.MergeFrom(reqq[4])

    return api_req(auth_type, api, access_token, scan_location, req, useauth=use_auth)


def get_api_endpoint(auth_type, access_token, scan_location, api=DEFAULT_API_URL, retry_count=DEFAULT_API_ENDPOINT_RETRIES):
    profile = get_profile(auth_type, access_token, api, None, scan_location)
    if retry_count < 0:
        while is_valid_profile(profile):
            print('[-] problems retrieving profile, retrying')
            profile = get_profile(auth_type, access_token, api, None, scan_location)
    else:
        for i in range(retry_count):
            print('[-] problems retrieving profile, retrying ({} out of {} retry attempts)'.format(i + 1, retry_count))
            if is_valid_profile(profile):
                break
            profile = get_profile(auth_type, access_token, api, None, scan_location)

    return 'https://%s/rpc' % profile.api_url if is_valid_profile(profile) else None


def is_valid_profile(profile):
    return profile is not None and profile.api_url is not None and profile.api_url != ""

def login_google(username, password):
    GOOGLE_LOGIN_ANDROID_ID = '9774d56d682e549c'
    GOOGLE_LOGIN_SERVICE= 'audience:server:client_id:848232511240-7so421jotr2609rmqakceuu1luuq0ptb.apps.googleusercontent.com'
    GOOGLE_LOGIN_APP = 'com.nianticlabs.pokemongo'
    GOOGLE_LOGIN_CLIENT_SIG = '321187995bc7cdc2b5fc91b11a96e2baa8602c62'

    login = perform_master_login(username, password, GOOGLE_LOGIN_ANDROID_ID)
    login = perform_oauth(username, login.get('Token', ''), GOOGLE_LOGIN_ANDROID_ID, GOOGLE_LOGIN_SERVICE, GOOGLE_LOGIN_APP,
                          GOOGLE_LOGIN_CLIENT_SIG)

    return login.get('Auth')


def login_ptc(username, password):
    session = requests.session()
    session.headers.update({'User-Agent': 'Niantic App'})
    session.verify = False

    print('[!] login for: {}'.format(username))
    print('[!] password for: {}'.format(password))
    head = {'User-Agent': 'Niantic App'}
    r = session.get(LOGIN_URL, headers=head)

    try:
        jdata = json.loads(r.content)
    except ValueError, e:
        print('login_ptc: could not decode JSON from {}'.format(r.content))
        return None

    # Maximum password length is 15 (sign in page enforces this limit, API does not)

    if len(password) > 15:
        print '[!] Trimming password to 15 characters'
        password = password[:15]

    data = {
        'lt': jdata['lt'],
        'execution': jdata['execution'],
        '_eventId': 'submit',
        'username': username,
        'password': password
    }
    r1 = session.post(LOGIN_URL, data=data, headers=head)

    try:
        ticket = re.sub('.*ticket=', '', r1.history[0].headers['Location'])
    except Exception, e:
        if DEBUG:
            print(r1.json()['errors'][0])
        return None

    data1 = {
        'client_id': 'mobile-app_pokemon-go',
        'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error',
        'client_secret': PTC_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'code': ticket
    }
    r2 = session.post(LOGIN_OAUTH, data=data1)
    access_token = re.sub('&expires.*', '', r2.content)
    access_token = re.sub('.*access_token=', '', access_token)
    return access_token


def login(username, password, login_fn=login_ptc, retry_count=DEFAULT_MAX_LOGIN_RETRIES):
    access_token = login_fn(username, password)
    if retry_count < 0:
        while access_token is not None:
            print('[-] login failed, retrying')
            access_token = login_fn(username, password)
    else:
        for i in range(retry_count):
            print '[-] login failed, retrying ({} out of {} retry attempts)'.format(i + 1, retry_count)
            access_token = login_fn(username, password)
            if access_token is not None:
                break
    return access_token


def raw_heartbeat(auth_type, api_endpoint, access_token, use_auth, scan_location):
    m4 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleInt()
    m.f1 = int(time.time() * 1000)
    m4.message = m.SerializeToString()
    m5 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleString()
    m.bytes = "05daf51635c82611d1aac95c0b051d3ec088a930"
    m5.message = m.SerializeToString()

    walk = sorted(get_neighbors(scan_location))

    m1 = pokemon_pb2.RequestEnvelop.Requests()
    m1.type = 106
    m = pokemon_pb2.RequestEnvelop.MessageQuad()
    m.f1 = ''.join(map(encode, walk))
    m.f2 = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    m.lat = scan_location[BIN_LAT_KEY]
    m.long = scan_location[BIN_LONG_KEY]
    m1.message = m.SerializeToString()
    response = get_profile(
        auth_type,
        access_token,
        api_endpoint,
        use_auth,
        scan_location,
        m1,
        pokemon_pb2.RequestEnvelop.Requests(),
        m4,
        pokemon_pb2.RequestEnvelop.Requests(),
        m5)
    try:
        payload = response.payload[0]
    except (AttributeError, IndexError):
        return
    h = pokemon_pb2.ResponseEnvelop.HeartbeatPayload()
    h.ParseFromString(payload)
    return h


def heartbeat(auth_type, api_endpoint, access_token, use_auth, scan_location, user_name):
    global is_valid
    while True:
        try:
            h = raw_heartbeat(auth_type, api_endpoint, access_token, use_auth, scan_location)
            return h
        except Exception, e:
            if DEBUG:
                print(e)
            print('[-] Heartbeat missed, retrying')
            is_valid[user_name] = False


def scan(auth_type, api_endpoint, access_token, use_auth, original_cell, user_data, initial_user_scan_location, step_limit=NUM_STEPS):
    steps = 0
    pos = 1
    x = 0
    y = 0
    dx = 0
    dy = -1
    scanner_location = initial_user_scan_location
    while steps < step_limit ** 2:
        original_lat = scanner_location[LAT_KEY]
        original_long = scanner_location[LONG_KEY]
        parent = CellId.from_lat_lng(LatLng.from_degrees(original_lat, original_long)).parent(15)

        h = heartbeat(auth_type, api_endpoint, access_token, use_auth, scanner_location, user_data[USER_NAME_KEY])
        hs = [h]
        seen = set([])
        for child in parent.children():
            latlng = LatLng.from_point(Cell(child).get_center())
            child_scan_location = generate_scan_location(latlng.lat().degrees, latlng.lng().degrees, 0)
            hs.append(heartbeat(auth_type, api_endpoint, access_token, use_auth, child_scan_location, user_data[USER_NAME_KEY]))

        visible = []

        for hh in hs:
            try:
                for cell in hh.cells:
                    for wild in cell.WildPokemon:
                        spawn_id_pokemon_id = wild.SpawnPointId + ':' + str(wild.pokemon.PokemonId)
                        if spawn_id_pokemon_id not in seen:
                            visible.append(wild)
                            seen.add(spawn_id_pokemon_id)
                    # if cell.Fort:
                    #     for Fort in cell.Fort:
                    #         if Fort.Enabled:
                    #             if Fort.GymPoints:
                    #                 add_gym(Fort.FortId, Fort.Team, Fort.Latitude, Fort.Longitude, Fort.GymPoints,
                    #                         pokemons[Fort.GuardPokemonId - 1]['Name'])
                    #             elif Fort.FortType:
                    #                 expire_time = 0
                    #                 if Fort.LureInfo.LureExpiresTimestampMs:
                    #                     expire_time = datetime \
                    #                         .fromtimestamp(Fort.LureInfo.LureExpiresTimestampMs / 1000.0) \
                    #                         .strftime("%H:%M:%S")
                    #                 add_pokestop(Fort.FortId, Fort.Latitude, Fort.Longitude, expire_time)

            except AttributeError:
                break

        for poke in visible:
            other = LatLng.from_degrees(poke.Latitude, poke.Longitude)
            diff = other - original_cell
            # print(diff)
            # difflat = diff.lat().degrees
            # difflng = diff.lng().degrees

            print("[+] (%s) %s is visible at (%s, %s) for %s seconds" % (
                poke.pokemon.PokemonId, pokemons[poke.pokemon.PokemonId - 1]['Name'], poke.Latitude, poke.Longitude,
                poke.TimeTillHiddenMs / 1000))

            timestamp = int(time.time())
            add_pokemon(poke.pokemon.PokemonId, pokemons[poke.pokemon.PokemonId - 1]['Name'], poke.Latitude,
                        poke.Longitude, timestamp, poke.TimeTillHiddenMs / 1000)

        prune()
        write_data_to_file()

        if (-step_limit / 2 < x <= step_limit / 2) and (-step_limit / 2 < y <= step_limit / 2):
            scanner_location = generate_scan_location((x * 0.0025) + user_data[LOCATION_KEY][LAT_KEY],
                                                      (y * 0.0025) + user_data[LOCATION_KEY][LONG_KEY],
                                                      0)
        if x == y or (x < 0 and x == -y) or (x > 0 and x == 1 - y):
            dx, dy = -dy, dx
        x, y = x + dx, y + dy
        steps += 1

        print('[+] Scan: %0.1f %%' % (((steps + (pos * .25) - .25) / step_limit ** 2) * 100))


def init_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--auth-type", help="Auth Type (google or ptc)")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-l", "--location", help="Location")
    parser.add_argument("--users-file", help="User data file (auth-type, username, password, and location)")
    parser.add_argument("-d", "--debug", help="Debug Mode", action='store_true')
    parser.set_defaults(DEBUG=False)

    return parser


def generate_access_list(args):
    users_file = args.users_file if args.users_file is not None else DEFAULT_USERS_FILE

    if args.username is not None and args.password is not None:
        username = args.username
        password = args.password
        with open(users_file, 'w') as f:
            access_list = [{USER_NAME_KEY: username, PASSWORD_KEY: password}]
            json.dump(access_list, f, indent=2)
    else:
        try:
            with open(users_file) as f:
                access_list = json.load(f)

            for access in access_list:
                username = access.get(USER_NAME_KEY, None)
                password = access.get(PASSWORD_KEY, None)
                if username is None or password is None:
                    print('[!] ' + users_file + ' file corrupt, reinsert username and password')
                    return None
        except IOError as e:
            print('[!] You must insert username and password first!')
            return None

    return access_list


def set_gmaps_data(gmaps_api_key, gmap_data_file):
    if gmaps_api_key is not None:
        with open(gmap_data_file, 'w') as f:
            gdata = {'GOOGLE_MAPS_API_KEY': gmaps_api_key}
            json.dump(gdata, f, indent=2)
    else:
        print('[-] Insert your GoogleMaps API key in config.json file!')


def print_user_details(login_payload):
    if login_payload is not None:
        print('[+] Login successful')

        if login_payload.payload:
            payload = login_payload.payload[0]
            profile = pokemon_pb2.ResponseEnvelop.ProfilePayload()
            profile.ParseFromString(payload)
            print('[+] Username: {}'.format(profile.profile.username))

            creation_time = datetime.fromtimestamp(int(profile.profile.creation_time) / 1000)
            print('[+] You are playing Pokemon Go since: {}'.format(
                creation_time.strftime('%Y-%m-%d %H:%M:%S'),
            ))

            for curr in profile.profile.currency:
                print('[+] {}: {}'.format(curr.type, curr.amount))
        else:
            print('[-] Profile payload empty')
    else:
        print('[-] Ooops...')


def generate_scan_location(lat, lng, alt):
    return {
        LAT_KEY: lat,
        LONG_KEY: lng,
        ALT_KEY: alt,
        BIN_LAT_KEY: f2i(lat),
        BIN_LONG_KEY: f2i(lng),
        BIN_ALT_KEY: f2i(alt)
    }


def run_poke_data_collection(user_data):
    global is_valid
    user_name = user_data[USER_NAME_KEY]

    while True:
        is_valid[user_name] = True
        initial_scan_location = generate_scan_location(user_data[LOCATION_KEY][LAT_KEY],
                                                       user_data[LOCATION_KEY][LONG_KEY],
                                                       user_data[LOCATION_KEY][ALT_KEY])

        if user_data[AUTH_TYPE_KEY] == 'google':
            access_token = login(user_name, user_data[PASSWORD_KEY], login_google)
        elif user_data[AUTH_TYPE_KEY] == 'ptc':
            access_token = login(user_name, user_data[PASSWORD_KEY])
        else:
            print('[-] Error logging in: No valid Auth Type')
            return

        if access_token is None:
            print('[-] Error logging in: possible wrong username/password')
            return

        print('[+] RPC Session Token: {} ...'.format(access_token[:25]))

        api_endpoint = get_api_endpoint(user_data[AUTH_TYPE_KEY], access_token, initial_scan_location)
        if api_endpoint is None:
            print('[-] RPC server offline')
            return
        print('[+] Received API endpoint: {}'.format(api_endpoint))

        response = get_profile(user_data[AUTH_TYPE_KEY], access_token, api_endpoint, None, initial_scan_location)
        print_user_details(response)

        origin_cell = LatLng.from_degrees(user_data[LOCATION_KEY][LAT_KEY], user_data[LOCATION_KEY][LAT_KEY])

        start_time = time.time()
        elapsed_time = time.time() - start_time
        while is_valid[user_name] and elapsed_time < REFRESH_TIME:
            scan(user_data[AUTH_TYPE_KEY], api_endpoint, access_token, response.unknown7, origin_cell, user_data, initial_scan_location)
            elapsed_time = time.time()


def generate_user_location(address):
    geolocator = GoogleV3()
    lat_long_regex = re.compile('^(\-?\d+(\.\d+)?),\s*(\-?\d+(\.\d+)?)$')
    location = {ADDRESS_KEY: address}
    if lat_long_regex.match(address):
        local_lat, local_lng = [float(x) for x in address.split(",")]
        lat_long_alt = {LAT_KEY: local_lat, LONG_KEY: local_lng, ALT_KEY: 0}
    else:
        loc = geolocator.geocode(address)
        lat_long_alt = {LAT_KEY: loc.latitude, LONG_KEY: loc.longitude, ALT_KEY: loc.altitude}
        print '[!] Your given location: {}'.format(loc.address.encode('utf-8'))

    location.update(lat_long_alt)
    print('[!] lat/long/alt: {} {} {}'.format(location[LAT_KEY], location[LONG_KEY], location[ALT_KEY]))
    return location


def generate_users_data(args):
    users_file = args.users_file if args.users_file is not None else DEFAULT_USERS_FILE

    if args.auth_type is not None and args.username is not None and args.password is not None and args.location is not None:
        users_data = [{
            AUTH_TYPE_KEY: args.auth_type,
            USER_NAME_KEY: args.username,
            PASSWORD_KEY: args.password,
            LOCATION_KEY: generate_user_location(args.location)
        }]
    else:
        try:
            with open(users_file) as f:
                users_data = json.load(f)

            for user_data in users_data:
                # TODO: Make these validation checks a function
                auth_type = user_data.get(AUTH_TYPE_KEY, None)
                if auth_type is None:
                    print('[!] Could not find value for \'{}\' in {}'.format(AUTH_TYPE_KEY, users_file))
                    return None
                user_name = user_data.get(USER_NAME_KEY, None)
                if user_name is None:
                    print('[!] Could not find value for \'{}\' in {}'.format(USER_NAME_KEY, users_file))
                    return None
                password = user_data.get(PASSWORD_KEY, None)
                if password is None:
                    print('[!] Could not find value for \'{}\' in {}'.format(PASSWORD_KEY, users_file))
                    return None
                location = user_data.get(LOCATION_KEY, None)
                if location is None:
                    print('[!] Could not find value for \'{}\' in {}'.format(LOCATION_KEY, users_file))
                    return None

                if not location.get(LAT_KEY, None) or not location.get(LONG_KEY, None) or not location.get(ALT_KEY, None):
                    user_data[LOCATION_KEY] = generate_user_location(location[ADDRESS_KEY])
        except IOError as e:
            print('[!] Error reading {}!'.format(users_file))
            return None

    return users_data


def main():
    full_path = os.path.realpath(__file__)
    (path, filename) = os.path.split(full_path)

    # TODO: This call may not be needed
    # write_data_to_file()

    parser = init_arg_parser()
    args = parser.parse_args()

    if args.debug:
        global DEBUG
        DEBUG = True
        print('[!] DEBUG mode on')

    users_data = generate_users_data(args)

    # set_location(args.location)
    set_gmaps_data(GMAPS_API_KEY, GMAP_DATA_FILE)

    global pokemons
    pokemons = json.load(open(path + '/pokemon.json'))

    pool = ThreadPool(len(users_data))
    pool.map(run_poke_data_collection, users_data)

if __name__ == '__main__':
    main()
