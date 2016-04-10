# door-web
Web interface for door unlocking

Authenticates the user against the [p2k12](https://github.com/bitraf/p2k12) member database.

Expects a shell script `bitraf-open-door.sh` to exist in `PATH` to actually open the door.
This script typically talks to a [dlock13](https://github.com/bitraf/dlock13) instance,
over SSH or [MQTT](https://en.wikipedia.org/wiki/MQTT).
