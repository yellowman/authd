CREATE TABLE login_branding (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 name text NOT NULL DEFAULT 'authd' CHECK (char_length(name) BETWEEN 1 AND 100),
 logo bytea NOT NULL DEFAULT ''::bytea CHECK (octet_length(logo)<=262144),
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO login_branding(singleton) VALUES(true);
