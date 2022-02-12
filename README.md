# Beeper media viewer
A simple web app that can download, decrypt and display encrypted Matrix media.

## Configuration variables

* `BMV_DATABASE_DRIVER` - Database driver to use, `postgres` and `sqlite3` are supported. Defaults to `sqlite3`.
* `BMV_DATABASE_URL` - Database connection string. Defaults to `beeper-media-viewer.db`.
* `BMV_LISTEN_ADDRESS` - Address to listen on. Defaults to `:29333`.
* `BMV_DEFAULT_HOMESERVER_URL` - The default homeserver URL to use for files.
  If not set, the homeserver URL will be resolved from the server part of the media file.
* `BMV_FORCE_DEFAULT_HOMESERVER` - Should the default homeserver URL be used even if the client provides one? Defaults to false.
* `BMV_NODE_ID` - Node ID for preventing conflicts between media shortcut IDs. Defaults to a random integer.
* `BMV_TRUST_FORWARD_HEADERS` - Should the `X-Forwarded-For` header be trusted when logging client IPs? Defaults to false.
