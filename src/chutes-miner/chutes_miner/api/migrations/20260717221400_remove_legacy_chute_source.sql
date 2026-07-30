-- migrate:up
-- This migration has not shipped. Preserve the production source columns and
-- their data while seedless readers stop depending on them.
SELECT 1;

-- migrate:down
-- The up migration is intentionally non-destructive.
SELECT 1;
