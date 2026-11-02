![The bench before any hand reaches it: the rough half of the meteorite on a folded cloth, fine metal dust in a pale fan beside it, the sawn half polished face up with its crossing bands catching cool light, amber jars and a saw silhouette behind, one warm lamp at the far end, no label anywhere](intro-banner.png)

# avr-VulnCodeLineRemediator

![The preparation bench with the opened meteorite at its centre, the diamond saw idle at the back, the field notebook open with ruled empty pages, and the name avr-vulncodelineremediator on the bone white specimen label taped to the bench edge below the slab](banner.png)

![A sawn meteorite slab seen flat from above, its Widmanstatten bands crossing at sharp angles, a shallow etched border at the edge, and a blank tag red label on a wire at the lower right, the heading plate](logo.png)

![Bench scene in three bands: the warm lamp brightens and dims slowly on the far shelf, a highlight travels across the polished slab face while the slab stays still and a dry etching brush strokes at long intervals, and metal dust motes drift down at the bench front](scene.svg)

Given a known vulnerability and a codebase, this tool scans for the lines that may need remediation and writes a patch file for them. The scan is a keyword line scan over Python files that parse (`ast.parse` is used only to confirm a file parses, not to match blocks): it fetches the search page for the vulnerability ID from the database base URL given, takes the text of the first cell of the first table on that page as the description, splits that text into keywords, and lists every line containing one of those keywords. A default run changes no scanned file; it only writes the patch file. Passing `--apply` applies the code changing patches in place, per file from the highest line number down. Suggestions that only add a comment, such as the `os.system` and `pickle.load` warnings, change no code, so they are written to the patch file as manual steps, are never auto applied, and are logged as manual steps, not as applied fixes.

> **Amber jar: a default run changes no scanned file.** It only writes the patch file. Passing `--apply` is the step that changes code, per file from the highest line number down.

> **Amber jar: comment only means by hand.** Suggestions that only add a comment, such as the `os.system` and `pickle.load` warnings, are written to the patch file as manual steps, are never auto applied, and are logged as manual steps, not as applied fixes.

![Section divider: a saw cut line with dust below it and three etched bands crossing it](sep-heavy.svg)

## Install
`git clone https://github.com/ShadowStrikeHQ/avr-vulncodelineremediator`

![Section divider: a saw cut line with dust below it and one etched band crossing it at the centre](sep-light.svg)

## Usage
`./avr-vulncodelineremediator [params]`

![Section divider: a saw cut line with dust below it and three etched bands crossing it](sep-heavy.svg)

## Parameters
- `-h`: Show help message and exit
- `--vulnerability_id`: No description provided
- `--codebase_path`: The path to the codebase to scan.
- `--output_patch_path`: The path to save the generated patch file. Defaults to 
- `--apply`: Apply code changing patches to the files in place. Without this flag a run only writes the patch file and changes no scanned file. Comment only suggestions are never applied; they appear in the patch file as manual steps.
- `--approval_required`: With `--apply`, ask before applying each patch. Has no effect without `--apply`.
- `--exploit_db_url`: The base URL of the Exploit Database to use for vulnerability information.

![Section divider: a saw cut line with dust below it and three etched bands crossing it](sep-heavy.svg)

## License
Copyright (c) ShadowStrikeHQ
