-- Seed default admin user
-- Email: admin@scanboy.local
-- Default password is documented in .env.example — change it after first login.
-- IMPORTANT: You must generate your own hash before running this migration:
-- node -e "require('bcrypt').hash('YOUR_PASSWORD',12).then(h=>console.log(h))"
-- Then replace the placeholder hash below with the output.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@scanboy.local') THEN
    INSERT INTO users (id, email, username, password_hash, role, status, mfa_enabled, force_password_change, created_at, updated_at)
    VALUES (
      uuid_generate_v4(),
      'admin@scanboy.local',
      'admin',
      '$2b$12$REPLACE_THIS_HASH_SEE_COMMENT_ABOVE',
      'admin',
      'active',
      false,
      true,
      NOW(),
      NOW()
    );
    RAISE NOTICE 'Default admin user created: admin@scanboy.local';
  ELSE
    RAISE NOTICE 'Admin user already exists, skipping seed.';
  END IF;
END $$;
