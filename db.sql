CREATE TABLE IF NOT EXISTS accounts (
        identifier text NOT NULL,
	private_key_hex text NOT NULL,
	public_key_hex text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS fake_account (
	fakeidentifier text NOT NULL,
	fake_private_key_hex text NOT NULL,
	fake_public_key_hex text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS fakeAccounts (
	identifier text NOT NULL,
	EncryptionKey text NOT NULL,
	time_generated text NOT NULL,
	hash text DEFAULT 'None',
	proof_of_work text DEFAULT 'None',
	proof_of_work_time text DEFAULT '0'
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS keys (
	identifier text NOT NULL,
        public_key text NOT NULL,
	private_key text NOT NULL,
	time_generated text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS encryption_key (
        public_key text NOT NULL,
	private_key text NOT NULL,
	time_generated text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS users (
        identifier text NOT NULL,
	public_key_hex text NOT NULL,
	public_key text DEFAULT 'Unknown',
	last_online text DEFAULT '0',
	protocols text NOT NULL
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

NEW_TABLE

CREATE TABLE IF NOT EXISTS connections (
	sender text NOT NULL,
	receiver text NOT NULL,
	times_connected text NOT NULL,
	time text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS trusted_nodes (
	identifier text NOT NULL
);
