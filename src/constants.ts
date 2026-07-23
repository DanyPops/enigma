export const STATE_DIRECTORY_NAME = "enigma";
export const DATABASE_FILENAME = "enigma.sqlite";
export const TOKEN_FILENAME = "token";
export const HANDLE_FILENAME = "handle.json";
export const SYSTEMD_UNIT_NAME = "enigma.service";

export const CREDENTIALS_DIRECTORY_NAME = "credentials";
export const MASTER_KEY_FILENAME = ".master";
export const SUPERVISOR_CONFIG_FILENAME = "daemons.json";

/** OS keyring service/account names for the master key (@napi-rs/keyring's Entry(service, name)). */
export const KEYRING_SERVICE = "danypops.enigma";
export const KEYRING_ACCOUNT = "master";
