CREATE TABLE IF NOT EXISTS accounts (
        identifier text NOT NULL,
	private_key_hex text NOT NULL,
	public_key_hex text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS keys (
	identifier text NOT NULL,
        public_key text NOT NULL,
	private_key text NOT NULL,
	time_generated text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS users (
        identifier text NOT NULL,
	public_key_hex text NOT NULL,
	public_key text DEFAULT 'Unknown',
	last_online text DEFAULT '0'
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS peers (
        peer text NOT NULL,
	identifier text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS test_peers (
        peer text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS banlist (
        peer text DEFAULT 'None',
	identifier text NOT NULL,
	time text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS last_logs (
        identifier text NOT NULL,
	time text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS last_posts (
        peer text NOT NULL,
	tx_hash text NOT NULL,
	time text NOT NULL
);
