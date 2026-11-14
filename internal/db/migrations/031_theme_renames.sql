-- +goose Up

-- Theme slugs were renamed from upstream project names to descriptive ones.
-- Rewrite the two places a slug is stored: the server default and each user's
-- override. The Go registry also accepts the legacy slugs as aliases, so an
-- un-migrated row still resolves; this migration makes the stored values match
-- the selector shown in the UI.

UPDATE settings SET value = 'cool-slate'   WHERE key = 'ui_theme' AND value = 'slate';
UPDATE settings SET value = 'arctic-blue'  WHERE key = 'ui_theme' AND value = 'nord';
UPDATE settings SET value = 'warm-retro'   WHERE key = 'ui_theme' AND value = 'gruvbox';
UPDATE settings SET value = 'sand-blue'    WHERE key = 'ui_theme' AND value = 'solarized';
UPDATE settings SET value = 'pastel-mauve' WHERE key = 'ui_theme' AND value = 'catppuccin';
UPDATE settings SET value = 'neon-indigo'  WHERE key = 'ui_theme' AND value = 'tokyo-night';
UPDATE settings SET value = 'dusk-rose'    WHERE key = 'ui_theme' AND value = 'rose-pine';
UPDATE settings SET value = 'forest-sage'  WHERE key = 'ui_theme' AND value = 'everforest';
UPDATE settings SET value = 'ink-wash'     WHERE key = 'ui_theme' AND value = 'kanagawa';
UPDATE settings SET value = 'warm-paper'   WHERE key = 'ui_theme' AND value = 'paper';
UPDATE settings SET value = 'clean-white'  WHERE key = 'ui_theme' AND value = 'github-light';
UPDATE settings SET value = 'studio-white' WHERE key = 'ui_theme' AND value = 'one-light';
UPDATE settings SET value = 'amber-sand'   WHERE key = 'ui_theme' AND value = 'ayu-light';

UPDATE users SET theme = 'cool-slate'   WHERE theme = 'slate';
UPDATE users SET theme = 'arctic-blue'  WHERE theme = 'nord';
UPDATE users SET theme = 'warm-retro'   WHERE theme = 'gruvbox';
UPDATE users SET theme = 'sand-blue'    WHERE theme = 'solarized';
UPDATE users SET theme = 'pastel-mauve' WHERE theme = 'catppuccin';
UPDATE users SET theme = 'neon-indigo'  WHERE theme = 'tokyo-night';
UPDATE users SET theme = 'dusk-rose'    WHERE theme = 'rose-pine';
UPDATE users SET theme = 'forest-sage'  WHERE theme = 'everforest';
UPDATE users SET theme = 'ink-wash'     WHERE theme = 'kanagawa';
UPDATE users SET theme = 'warm-paper'   WHERE theme = 'paper';
UPDATE users SET theme = 'clean-white'  WHERE theme = 'github-light';
UPDATE users SET theme = 'studio-white' WHERE theme = 'one-light';
UPDATE users SET theme = 'amber-sand'   WHERE theme = 'ayu-light';

-- +goose Down

-- Best effort: restore the legacy slugs. Alias resolution makes either set
-- readable, so a partial rollback cannot produce an unthemed page.
UPDATE settings SET value = 'slate'       WHERE key = 'ui_theme' AND value = 'cool-slate';
UPDATE settings SET value = 'nord'        WHERE key = 'ui_theme' AND value = 'arctic-blue';
UPDATE settings SET value = 'gruvbox'     WHERE key = 'ui_theme' AND value = 'warm-retro';
UPDATE settings SET value = 'solarized'   WHERE key = 'ui_theme' AND value = 'sand-blue';
UPDATE settings SET value = 'catppuccin'  WHERE key = 'ui_theme' AND value = 'pastel-mauve';
UPDATE settings SET value = 'tokyo-night' WHERE key = 'ui_theme' AND value = 'neon-indigo';
UPDATE settings SET value = 'rose-pine'   WHERE key = 'ui_theme' AND value = 'dusk-rose';
UPDATE settings SET value = 'everforest'  WHERE key = 'ui_theme' AND value = 'forest-sage';
UPDATE settings SET value = 'kanagawa'    WHERE key = 'ui_theme' AND value = 'ink-wash';
UPDATE settings SET value = 'paper'       WHERE key = 'ui_theme' AND value = 'warm-paper';
UPDATE settings SET value = 'github-light' WHERE key = 'ui_theme' AND value = 'clean-white';
UPDATE settings SET value = 'one-light'   WHERE key = 'ui_theme' AND value = 'studio-white';
UPDATE settings SET value = 'ayu-light'   WHERE key = 'ui_theme' AND value = 'amber-sand';

UPDATE users SET theme = 'slate'       WHERE theme = 'cool-slate';
UPDATE users SET theme = 'nord'        WHERE theme = 'arctic-blue';
UPDATE users SET theme = 'gruvbox'     WHERE theme = 'warm-retro';
UPDATE users SET theme = 'solarized'   WHERE theme = 'sand-blue';
UPDATE users SET theme = 'catppuccin'  WHERE theme = 'pastel-mauve';
UPDATE users SET theme = 'tokyo-night' WHERE theme = 'neon-indigo';
UPDATE users SET theme = 'rose-pine'   WHERE theme = 'dusk-rose';
UPDATE users SET theme = 'everforest'  WHERE theme = 'forest-sage';
UPDATE users SET theme = 'kanagawa'    WHERE theme = 'ink-wash';
UPDATE users SET theme = 'paper'       WHERE theme = 'warm-paper';
UPDATE users SET theme = 'github-light' WHERE theme = 'clean-white';
UPDATE users SET theme = 'one-light'   WHERE theme = 'studio-white';
UPDATE users SET theme = 'ayu-light'   WHERE theme = 'amber-sand';
