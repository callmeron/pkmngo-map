#!/usr/bin/python
import pkmn_api
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="PTC Username")
    parser.add_argument("-p", "--password", help="PTC Password")
    parser.add_argument("-l", "--location", help="Location", required=True)
    parser.add_argument("-d", "--debug", help="Debug Mode", action='store_true')
    parser.set_defaults(DEBUG=False)
    args = parser.parse_args()

    config = {
        "USERNAME":args.username,
        "PASSWORD":args.password,
        "LOCATION":args.location,
        "DEBUG":args.debug
    }

    pkmn_api.init(config)


if __name__ == '__main__':
    main()
