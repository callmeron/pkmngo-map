# PkmnGo Map

This is a Work-In-Progress attempt to merge all Pokemon-Go-API Python project.

Feature will be developed on base of the Project maintainer's view, so Pull-Request that don't follow
his views will be rejected.

* USE AT YOUR OWN RISK, Ban may occour!
* Not so User-Friendly
* Includes protobuf file
* Ugly code

This version works only with **PokemonTrainerClub** account.<br/>
**Don't use your official account or you may end up Banned.**

**Don't refresh Gyms and Pokestop data many time on Phone, it will consume much bandwith**

## Todo
* One Click Deploy on Heroku like [emeth-/pokelocater/](https://github.com/emeth-/pokelocater/)
* Save in localstorage Hide Pokemon

## Screen
![Screen2](https://i.imgur.com/SeXBw9Y.png)

Another screen https://i.imgur.com/mpLvARC.png

## Instructions

Generate a Google Maps API key here: https://console.developers.google.com/apis/credentials

Use Python2.7 for better compatibility.

### Linux/macOS
* `pip install -r requirements.txt`
* Put Google Maps API key in `config.json`
* Syntax: `./run.sh [user] [pass] "[location]"`
* Open another terminal in the project location and run `cd web; python -m SimpleHTTPServer 8000`
* Run your browser to `http://localhost:8000`

### Windows
* Frist run `pip.exe install -r [location requirements.txt]`, <br/>Example : `C:\Python27\Scripts\pip.exe install -r C:\Users\Royal\Downloads\pkmngo-map-maps\requirements.txt`
* Put Google Maps API key in `config.json`
* Start `run.bat` and enter in prompts for username, password, and location
* Open browser to `http://localhost:8000`

Additional windows help here: https://www.reddit.com/r/pokemongodev/comments/4t8ohw/autoupdating_pokemon_go_map_scanner/d5g7xh80

### Docker
* Modify docker-compose.yml to set your USERNAME, PASSWORD, LOCATION and GOOGLE_MAPS_KEY (for best results, anyway)
* Run `docker-compose up` for great justice.

## Donate
My Bitcoin address is `1GV4ckHwhsqn9UAwgM8qFYArA8njCqZ21y`

## License
See LICENSE file

## Credits
Thanks a lot to [Mila432](https://github.com/Mila432/Pokemon_Go_API), [Tejado](https://github.com/tejado/pokemongo-api-demo) for base API<br/>
Thanks to [Leegao](https://github.com/leegao/pokemongo-api-demo/tree/simulation) for Pokemon scanning<br/>
Thanks to [AHAAAAAAA](https://github.com/AHAAAAAAA/PokemonGo-Map) for Gym/PokeStop scanning</br>
Thanks to [memelyfe](https://github.com/memelyfe/pokemongo-api-demo/tree/maps) for PokeMap</br>

Thanks to all [/r/pokemongodev](https://www.reddit.com/r/pokemongodev/) subreddit
