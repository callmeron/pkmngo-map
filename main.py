#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import struct
import time
from datetime import datetime

import requests
from geopy.geocoders import GoogleV3
from google.protobuf.internal import encoder

import pokemon_pb2

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


def get_neighbors():
    origin_cell = CellId.from_lat_lng(LatLng.from_degrees(FLOAT_LAT, FLOAT_LONG)).parent(15)
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

PASSWORD_KEY = 'PASSWORD'
USERNAME_KEY = 'USERNAME'
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

is_valid = True

DEBUG = False
COORDS_LATITUDE = 0
COORDS_LONGITUDE = 0
COORDS_ALTITUDE = 0
FLOAT_LAT = 0
FLOAT_LONG = 0
deflat, deflng = 0, 0
default_step = 0.001

# poke_data_lock;

poke_data = {
    'pokemon': {},
    'pokestop': {},
    'gym': {}
}

NUM_STEPS = 10
PKMN_DATA_FILE = os.path.join('web', 'pkmn.json')
PKSTOP_DATA_FILE = os.path.join('web', 'pkstop.json')
GYM_DATA_FILE = os.path.join('web', 'gym.json')
GMAP_DATA_FILE = os.path.join('web', 'gmap.json')

REFRESH_TIME = 1200

DEFAULT_ACCESS_FILE = 'access.json'


def f2i(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def f2h(x):
    return hex(struct.unpack('<Q', struct.pack('<d', x))[0])


def h2f(x):
    return struct.unpack('<d', struct.pack('<Q', int(x, 16)))[0]


def prune():
    # prune despawned pokemon
    cur_time = int(time.time())
    for (pokehash, poke) in poke_data['pokemon'].items():
        poke['timeleft'] = poke['timeleft'] - (cur_time - poke['timestamp'])
        poke['timestamp'] = cur_time
        if poke['timeleft'] <= 0:
            del poke_data['pokemon'][pokehash]


def write_data_to_file():
    prune()

    # different file for bandwidth save
    with open(PKMN_DATA_FILE, 'w') as f:
        json.dump(poke_data['pokemon'], f, indent=2)

    with open(PKSTOP_DATA_FILE, 'w') as f:
        json.dump(poke_data['pokestop'], f, indent=2)

    with open(GYM_DATA_FILE, 'w') as f:
        json.dump(poke_data['gym'], f, indent=2)


def add_pokemon(poke_id, name, lat, lng, timestamp, timeleft):
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
            'lat': lat,
            'lng': lng,
            'timestamp': timestamp,
            'timeleft': timeleft
        }


def add_pokestop(pokestop_id, lat, lng, timeleft):
    if pokestop_id in poke_data[('%s' % POKESTOP_KEY)]:
        poke_data[POKESTOP_KEY][pokestop_id]['timeleft'] = timeleft
    else:
        poke_data[POKESTOP_KEY][pokestop_id] = {
            'id': pokestop_id,
            'lat': lat,
            'lng': lng,
            'timeleft': timeleft
        }


def add_gym(gym_id, team, lat, lng, points, pokemon_guard):
    if gym_id in poke_data[GYM_KEY]:
        poke_data[GYM_KEY][gym_id]['team'] = team
        poke_data[GYM_KEY][gym_id]['points'] = points
        poke_data[GYM_KEY][gym_id]['guard'] = pokemon_guard
    else:
        poke_data[GYM_KEY][gym_id] = {
            'id': gym_id,
            'team': team,
            'lat': lat,
            'lng': lng,
            'points': points,
            'guard': pokemon_guard
        }


def set_location(location_name):
    geolocator = GoogleV3()
    prog = re.compile('^(\-?\d+(\.\d+)?),\s*(\-?\d+(\.\d+)?)$')
    global deflat
    global deflng
    if prog.match(location_name):
        local_lat, local_lng = [float(x) for x in location_name.split(",")]
        alt = 0
        deflat, deflng = local_lat, local_lng
    else:
        loc = geolocator.geocode(location_name)
        deflat, deflng = local_lat, local_lng = loc.latitude, loc.longitude
        alt = loc.altitude
        print '[!] Your given location: {}'.format(loc.address.encode('utf-8'))

    print('[!] lat/long/alt: {} {} {}'.format(local_lat, local_lng, alt))
    set_location_coords(local_lat, local_lng, alt)


def set_location_coords(lat, lng, alt):
    global COORDS_LATITUDE, COORDS_LONGITUDE, COORDS_ALTITUDE
    global FLOAT_LAT, FLOAT_LONG
    FLOAT_LAT = lat
    FLOAT_LONG = lng
    COORDS_LATITUDE = f2i(lat)  # 0x4042bd7c00000000 # f2i(lat)
    COORDS_LONGITUDE = f2i(lng)  # 0xc05e8aae40000000 #f2i(lng)
    COORDS_ALTITUDE = f2i(alt)


def get_location_coords():
    return COORDS_LATITUDE, COORDS_LONGITUDE, COORDS_ALTITUDE


def api_req(api_endpoint, access_token, *mehs, **kw):
    while True:
        try:
            p_req = pokemon_pb2.RequestEnvelop()
            p_req.rpc_id = 1469378659230941192

            p_req.unknown1 = 2

            p_req.latitude, p_req.longitude, p_req.altitude = get_location_coords()

            p_req.unknown12 = 989

            if 'useauth' not in kw or not kw['useauth']:
                p_req.auth.provider = 'ptc'
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


def get_profile(access_token, api, use_auth, *reqq):
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

    return api_req(api, access_token, req, useauth=use_auth)


def get_api_endpoint(access_token, api=DEFAULT_API_URL, retry_count=DEFAULT_API_ENDPOINT_RETRIES):
    profile = get_profile(access_token, api, None)
    if retry_count < 0:
        while is_valid_profile(profile):
            print('[-] problems retrieving profile, retrying')
            profile = get_profile(access_token, api, None)
    else:
        for i in range(retry_count):
            print('[-] problems retrieving profile, retrying ({} out of {} retry attempts)'.format( i + 1, retry_count))
            profile = get_profile(access_token, api, None)
            if is_valid_profile(profile):
                break

    return 'https://%s/rpc' % profile.api_url if is_valid_profile(profile) else None


def is_valid_profile(profile):
    return profile is not None and profile.api_url is not None and profile.api_url != ""


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


def raw_heartbeat(api_endpoint, access_token, response):
    m4 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleInt()
    m.f1 = int(time.time() * 1000)
    m4.message = m.SerializeToString()
    m5 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleString()
    m.bytes = "05daf51635c82611d1aac95c0b051d3ec088a930"
    m5.message = m.SerializeToString()

    walk = sorted(get_neighbors())

    m1 = pokemon_pb2.RequestEnvelop.Requests()
    m1.type = 106
    m = pokemon_pb2.RequestEnvelop.MessageQuad()
    m.f1 = ''.join(map(encode, walk))
    m.f2 = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    m.lat = COORDS_LATITUDE
    m.long = COORDS_LONGITUDE
    m1.message = m.SerializeToString()
    response = get_profile(
        access_token,
        api_endpoint,
        response.unknown7,
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


def heartbeat(api_endpoint, access_token, response):
    global is_valid
    while True:
        try:
            h = raw_heartbeat(api_endpoint, access_token, response)
            return h
        except Exception, e:
            if DEBUG:
                print(e)
            print('[-] Heartbeat missed, retrying')
            is_valid = False


def scan(api_endpoint, access_token, response, origin_lat_long, pokemons, step_limit=NUM_STEPS):
    steps = 0
    pos = 1
    x = 0
    y = 0
    dx = 0
    dy = -1
    while steps < step_limit ** 2:
        original_lat = FLOAT_LAT
        original_long = FLOAT_LONG
        parent = CellId.from_lat_lng(LatLng.from_degrees(FLOAT_LAT, FLOAT_LONG)).parent(15)

        h = heartbeat(api_endpoint, access_token, response)
        hs = [h]
        seen = set([])
        for child in parent.children():
            latlng = LatLng.from_point(Cell(child).get_center())
            set_location_coords(latlng.lat().degrees, latlng.lng().degrees, 0)
            hs.append(heartbeat(api_endpoint, access_token, response))
        set_location_coords(original_lat, original_long, 0)

        visible = []

        for hh in hs:
            try:
                for cell in hh.cells:
                    for wild in cell.WildPokemon:
                        spawn_id_pokemon_id = wild.SpawnPointId + ':' + str(wild.pokemon.PokemonId)
                        if spawn_id_pokemon_id not in seen:
                            visible.append(wild)
                            seen.add(spawn_id_pokemon_id)
                    if cell.Fort:
                        for Fort in cell.Fort:
                            if Fort.Enabled:
                                if Fort.GymPoints:
                                    add_gym(Fort.FortId, Fort.Team, Fort.Latitude, Fort.Longitude, Fort.GymPoints,
                                            pokemons[Fort.GuardPokemonId - 1]['Name'])
                                elif Fort.FortType:
                                    expire_time = 0
                                    if Fort.LureInfo.LureExpiresTimestampMs:
                                        expire_time = datetime \
                                            .fromtimestamp(Fort.LureInfo.LureExpiresTimestampMs / 1000.0) \
                                            .strftime("%H:%M:%S")
                                    add_pokestop(Fort.FortId, Fort.Latitude, Fort.Longitude, expire_time)

            except AttributeError:
                break

        for poke in visible:
            other = LatLng.from_degrees(poke.Latitude, poke.Longitude)
            diff = other - origin_lat_long
            # print(diff)
            difflat = diff.lat().degrees
            difflng = diff.lng().degrees

            print("[+] (%s) %s is visible at (%s, %s) for %s seconds" % (
                poke.pokemon.PokemonId, pokemons[poke.pokemon.PokemonId - 1]['Name'], poke.Latitude, poke.Longitude,
                poke.TimeTillHiddenMs / 1000))

            timestamp = int(time.time())
            add_pokemon(poke.pokemon.PokemonId, pokemons[poke.pokemon.PokemonId - 1]['Name'], poke.Latitude,
                        poke.Longitude, timestamp, poke.TimeTillHiddenMs / 1000)

        write_data_to_file()

        if (-step_limit / 2 < x <= step_limit / 2) and (-step_limit / 2 < y <= step_limit / 2):
            set_location_coords((x * 0.0025) + deflat, (y * 0.0025) + deflng, 0)
        if x == y or (x < 0 and x == -y) or (x > 0 and x == 1 - y):
            dx, dy = -dy, dx
        x, y = x + dx, y + dy
        steps += 1

        print('[+] Scan: %0.1f %%' % (((steps + (pos * .25) - .25) / step_limit ** 2) * 100))


def init_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="PTC Username")
    parser.add_argument("-p", "--password", help="PTC Password")
    parser.add_argument("-l", "--location", help="Location", required=True)
    parser.add_argument("-a", "--access-file", help="Access file")
    parser.add_argument("-d", "--debug", help="Debug Mode", action='store_true')
    parser.set_defaults(DEBUG=False)

    return parser


def generate_access_dict(args):
    access_file = args.access_file if args.access_file is not None else DEFAULT_ACCESS_FILE

    if args.username is not None and args.password is not None:
        username = args.username
        password = args.password
        with open(access_file, 'w') as f:
            access = {USERNAME_KEY: username, PASSWORD_KEY: password}
            json.dump(access, f, indent=2)
    else:
        try:
            with open(access_file) as f:
                access = json.load(f)

            username = access.get(USERNAME_KEY, None)
            password = access.get(PASSWORD_KEY, None)
            if username is None or password is None:
                print('[!] ' + access_file + ' file corrupt, reinsert username and password')
                return None
        except IOError as e:
            print('[!] You must insert username and password first!')
            return None

    return access


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

        if login_payload.payload != '':
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


def main():
    full_path = os.path.realpath(__file__)
    (path, filename) = os.path.split(full_path)

    write_data_to_file()
    pokemons = json.load(open(path + '/pokemon.json'))

    parser = init_arg_parser()
    args = parser.parse_args()

    if args.debug:
        global DEBUG
        DEBUG = True
        print('[!] DEBUG mode on')

    set_location(args.location)
    access_data = generate_access_dict(args)

    set_gmaps_data(GMAPS_API_KEY, GMAP_DATA_FILE)

    while True:
        global is_valid
        access_token = login(access_data[USERNAME_KEY], access_data[PASSWORD_KEY])

        if access_token is None:
            print('[-] Error logging in: possible wrong username/password')
            return

        print('[+] RPC Session Token: {} ...'.format(access_token[:25]))

        api_endpoint = get_api_endpoint(access_token)
        if api_endpoint is None:
            print('[-] RPC server offline')
            return
        print('[+] Received API endpoint: {}'.format(api_endpoint))

        response = get_profile(access_token, api_endpoint, None)
        print_user_details(response)

        origin_cell = LatLng.from_degrees(FLOAT_LAT, FLOAT_LONG)

        start_time = time.time()
        elapsed_time = time.time() - start_time
        while is_valid and elapsed_time < REFRESH_TIME:
            scan(api_endpoint, access_token, response, origin_cell, pokemons)
            elapsed_time = time.time()


if __name__ == '__main__':
    main()
