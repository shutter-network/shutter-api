# API key management

This applies, if you're operating shutter-api with rate limiting/api keys enabled (see `docker-compose.rate_limit.yaml` and `apikeys/apikeys.py` for more details), via `docker compose`.

Keys are stored in `shutter-api/data/keys.csv`.

There is a script on `shutter-api.shutter.network:shutter-api/add-apikey.sh` for adding new keys while the `compose` stack is running. It executes the python script from `apikeys/apikeys.py` inside the `docker compose` environment (see header of the python script for more documentation).

When you execute it, it will ask for an email address or other reference for a new key, that will be added to `keys.csv`.

If you manually change the contents of `keys.csv`, for example to remove a key, run `add-apikey.sh` and don't give a new keys reference -- that will compile the edited `.csv` and restart the webserver.
