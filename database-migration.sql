-- Migration: Change invoice table ID columns from INTEGER to BIGINT
-- Run this SQL on your PostgreSQL database

-- 1. Change the ID column to BIGINT
ALTER TABLE invoices ALTER COLUMN id TYPE BIGINT;

-- 2. Change the user_id column to BIGINT (if users table also uses BIGINT)
ALTER TABLE invoices ALTER COLUMN user_id TYPE BIGINT;

-- 3. If you also need to change the users table ID column:
-- ALTER TABLE users ALTER COLUMN id TYPE BIGINT;

-- 4. Verify the changes
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'invoices' 
AND column_name IN ('id', 'user_id'); 