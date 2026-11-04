CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.users (
	id            uuid        PRIMARY KEY,
	name          text        NOT NULL,
	email         text        NOT NULL,
	password_hash text,
	created_at    timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT users_email_lower CHECK (email = lower(email))
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON auth.users (email);

-- Profil (Fase 7): padanan UserName, PhoneNumber, Bio, dan AvatarUrl pada ApplicationUser sumber.
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS user_name    text;
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS phone_number text;
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS bio          text;
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS avatar_url   text;
CREATE UNIQUE INDEX IF NOT EXISTS users_user_name_key ON auth.users (lower(user_name)) WHERE user_name IS NOT NULL;