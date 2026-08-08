# Vendored webfonts

Self-hosted so the dashboard makes zero third-party network requests
(previously loaded from `https://rsms.me/inter/inter.css` on every page).

| File | Font | License |
|---|---|---|
| `inter-latin-{400,500,600}-normal.woff2` | [Inter](https://rsms.me/inter/) | SIL Open Font License 1.1 |
| `jetbrains-mono-latin-{400,600}-normal.woff2` | [JetBrains Mono](https://www.jetbrains.com/lp/mono/) | SIL Open Font License 1.1 |

Both fonts are free to embed and redistribute under the OFL. Files sourced
from a local Astro reference project (`designs/colorion-toggles`, itself
built on these same self-hosted font subsets) rather than re-downloaded,
since they're identical latin-subset WOFF2 builds.

To update: download the latest release from each font's site, subset to
latin if desired, and replace the files here — no code changes needed
beyond the `@font-face` `src` paths in `static/style.css` if filenames change.
