# Tippy Dashboard

Small static dashboard for triaging IOC records in a browser with no build step.

## What It Does

- Splits records into `Pending` and `Completed` tabs
- Supports per-tab search and sort controls
- Stores changes in `localStorage`
- Lets analysts capture notes, select rows, and copy defanged IOCs
- Shows quick external lookup links for each IOC

## Files

- `index.html`: dashboard structure and controls
- `style.css`: layout, table styling, tooltip styling, and responsive rules
- `script.js`: data normalization, rendering, event handling, search, sorting, and clipboard logic

## Run It

Open `index.html` in a browser.

## Notes

- Dashboard state is saved under the `tippyData` key in browser `localStorage`
- "Start Auto IRL" is intentionally disabled until that workflow is defined
- If stored data is malformed, the app falls back to the bundled sample data