# CF7 Security Patches

Unofficial fix for **CVE-2026-104246** in *Contact Form 7 Signature Addon* 4.2.2, delivered as a single-file WordPress must-use plugin.

*Contact Form 7 Signature Addon* (by Breizhtorm) lets a visitor make a form e-mail an unrelated file from `wp-content`. The plugin has no fixed release. This file blocks that, without changing the addon's own files.

> [!WARNING]
> **Use at your own risk.** This is an unofficial, independent patch. It is not written, reviewed or endorsed by Breizhtorm, by the Contact Form 7 project, by the authors of any other plugin named here, or by WordPress.org. It is provided "as is", without warranty of any kind. You install and use it entirely on your own responsibility. Test it on a staging copy of your site and keep a backup. It reduces one specific risk; it does not make a site secure and it is not a substitute for an official fix or for replacing an unmaintained plugin.

## Status of the original plugin

As of 12 November 2026:

- WPScan lists the vulnerability as affecting all versions up to 4.2.2, with "No known fix".
- The plugin page on wordpress.org says it was closed on 6 October 2026, "pending a full review".
- The last release is 4.2.2.

If an official fixed version appears, install it and remove this file.

## What it checks

The file loads before all normal plugins, then checks for each problem below whether it is still present on the site. It acts only where it is.

| Problem | Plugin | Counted as present when | What this file does |
| --- | --- | --- | --- |
| [CVE-2026-104246](https://wpscan.com/vulnerability/e56dc60b-9232-43f2-8d57-fe9452c85281/) | Contact Form 7 Signature Addon (Breizhtorm) | The addon is active and is version 4.2.2 or older, or the flawed code is still in its files | **Applies the patch** |
| CVE-2026-94589 | Extensions For CF7 (HT Plugins), folder `extensions-for-cf7` | That plugin is active in a version older than 3.4.6 | Shows a warning to update to 3.4.6. No patch |
| [CVE-2026-25863](https://www.vulncheck.com/advisories/conditional-fields-for-contact-form-7-dos-via-uncontrolled-resource-consumption) | Conditional Fields for Contact Form 7 | That plugin is active in a version older than 2.7.3 | Shows a warning to update to 2.7.3. No patch |

The second and third problems were fixed by their own authors. Updating is the fix, so this file only detects and warns.

CVE-2026-94589 belongs to the HT Plugins plugin. It is not in *Conditional Fields for Contact Form 7* and not in the Breizhtorm addon.

## How the patch for CVE-2026-104246 works

The addon builds an e-mail attachment path from the value posted in a signature field. The patch has four layers:

1. **Handlers replaced.** The addon's two mail handlers are unhooked and replaced by hardened ones. Attachments come only from a server-side list of the files written during the current request, never from a posted value.
2. **Value validated.** A signature field may hold only a real PNG data URI, which is what the signature pad produces, or nothing. Anything else fails validation and is blanked before other code sees it. The blanking does not depend on validation, so it also covers a field inside a hidden *Conditional Fields* group, where validation is skipped. Limits: 2 MB and 10,000 x 10,000 px per signature.
3. **Hardening.** Only the form's own signature fields are processed. The `inline` and `attachment` options are read from the form configuration, not from the request. Stored signature files get a random token in their name.
4. **Last check on outgoing mail.** Any attachment that points through the signatures folder to somewhere else is dropped.

Layers 2 and 4 keep working even if the addon's handlers cannot be unhooked. The status page then shows "Present - partly patched".

If a version of the addon newer than 4.2.2 is installed and the flawed code is no longer found, the patch is not applied. That check is a text match on the addon's code. Treat it as an estimate, not as proof.

## Requirements

- WordPress 5.0 or later, PHP 5.6 or later (declared; see "How it was tested" for what was actually run).
- Contact Form 7 with Contact Form 7 Signature Addon 4.2.2.
- Access to the site's files (FTP, SFTP or the host's file manager).

## Installation

1. Download `cf7-security-patches.php` from the latest release.
2. Upload it to `wp-content/mu-plugins/`. Create the folder if it does not exist.
3. Leave *Contact Form 7 Signature Addon* active and unchanged.

There is nothing to activate. A must-use plugin cannot be installed from **Plugins > Add New**.

## Check that it is working

1. **Plugins > Must-Use** lists "CF7 Security Patches (Signature Addon CVE-2026-104246)".
2. **Tools > CF7 Security Patches** shows one row per problem. The CVE-2026-104246 row must read **Present - patched**.
3. Send a test form with a signature and check that the e-mail arrives with the signature image.

| Status | Meaning |
| --- | --- |
| Not relevant | The plugin is not active. Nothing is done |
| Not present | The plugin is active in a fixed version, or the flawed code was not found. Nothing is done |
| Present - patched | The problem is present and the patch is fully applied |
| Present - partly patched | The addon's handlers could not be replaced. Crafted values are still blocked; the other hardening is not in effect |
| Present - NOT patched | The patch was switched off in `wp-config.php` |
| Present - update needed | Update that plugin to its fixed version. This file only warns |

## Switching it off and removing it

To switch it off without deleting the file, add this line to `wp-config.php`:

```php
define( 'CF7_SECURITY_PATCHES_DISABLED', true );
```

The site is exposed again while that line is there.

To remove it, delete the file. One small row named `cf7secpatches_sigcode` may remain in the options table and can be deleted.

## What changes for your forms

- A signature in the mail body, a signature as an attachment, and the `attachment` and `inline` options keep working.
- New signature files have longer names. Existing files are not renamed.
- A signature field that receives something other than a drawing is rejected and the form is not sent.

## Known limitations

- **Not a guarantee.** It was tested on a test install, not on your site.
- **Security scanners keep reporting the addon.** They compare version numbers, and the addon's files are unchanged at 4.2.2.
- **It protects only while the file is in place** and the off switch is not set.
- **Old signature files** in `uploads/wpcf7_signatures/` keep their guessable names and stay publicly reachable. Signature files are never deleted automatically.
- **The signature image is stored when the form is posted**, before Contact Form 7's validation and spam checks. That is the addon's design.
- **First click on Send.** In the test environment the addon's own script sent an empty signature on the first click and the drawing only on the second. This happened the same way with and without the patch. Your site may behave differently.
- **Other plugins were not audited.** For *Conditional Fields for Contact Form 7* and *Extensions For CF7* this file checks a version number only.
- **Addon versions older than 4.2.2 were not tested.**

## Advanced: filters

| Filter | Default | Purpose |
| --- | --- | --- |
| `cf7sigfix_max_signature_bytes` | `2097152` | Largest accepted signature image, in bytes |
| `cf7sigfix_max_signature_side` | `10000` | Largest accepted width or height, in pixels |
| `cf7sigfix_max_signatures_per_submission` | `20` | Most signature images stored for one submission |
| `cf7sigfix_replace_addon_handlers` | `true` | Return `false` to leave the addon's handlers hooked (layers 2 and 4 only) |

## How it was tested

Test install, not a production site: WordPress 7.1.4, Contact Form 7 6.2.5, Conditional Fields for Contact Form 7 2.8.6, Contact Form 7 Signature Addon 4.2.2, PHP 8.3, SQLite database. Outgoing mail was captured, not sent.

- Without the patch the problem was reproduced, including through a *Conditional Fields* group.
- With the patch the same request was rejected, and no unrelated file was attached with any single layer left on its own.
- Normal use kept working, including a signature drawn with the mouse in Chromium.
- 81 automated checks passed on version 1.0.1.

No proof-of-concept request is published here.

## Reporting a problem

- A bug in this patch: open an issue. Do not include working exploit requests or private data.
- A way around the patch: report it privately through the repository's **Security** tab if private reporting is enabled, otherwise contact the maintainer before posting details.

## Release checksums

| Version | File | SHA-256 |
| --- | --- | --- |
| 1.0.1 | `cf7-security-patches.php` | `dc88254c5ec7545660ae9b08674b1baff355ff03661197612dd8a86d70108f49` |

## Credits

- *Contact Form 7 Signature Addon* is by Breizhtorm and is licensed under GPL-2.0. This project does not include or redistribute it.
- WPScan credits Kiran Krishnakumar as the researcher who reported CVE-2026-104246.

This project is not affiliated with any of them.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE). The software comes with no warranty; see sections 11 and 12 of the license.

## Changelog

### 1.0.1

- Disclaimer added to the file header, the plugin description and the status page. No functional change.

### 1.0.0

- First version.
