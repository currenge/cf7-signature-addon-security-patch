=== CF7 Security Patches (Signature Addon CVE-2026-104246) ===
Tags: contact form 7, signature, security, patch, mu-plugin
Requires at least: 5.0
Tested up to: 7.1
Requires PHP: 5.6
Stable tag: 1.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Unofficial fix for CVE-2026-104246 in Contact Form 7 Signature Addon 4.2.2, as a single-file must-use plugin.

== USE AT YOUR OWN RISK ==

This is an unofficial, independent patch. It is not written, reviewed or
endorsed by Breizhtorm, by the Contact Form 7 project, by the authors of any
other plugin named here, or by WordPress.org.

It is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express or implied. You
install and use it entirely at your own risk and on your own responsibility.
In no event are the authors liable for any claim, damage, data loss or other
liability arising from its use.

Test it on a staging copy of your site and keep a backup. It reduces one
specific risk. It does not make a site secure, and it is not a substitute for
an official fix or for replacing an unmaintained plugin.

== Description ==

Contact Form 7 Signature Addon (by Breizhtorm) adds a signature field to
Contact Form 7. Visitors sign by hand on a canvas, and the signature is sent
with the form's e-mail, so a form can be submitted signed.

Versions up to 4.2.2 of that plugin have a security flaw, CVE-2026-104246.
The addon builds an e-mail attachment path from the value posted in the
signature field, so a crafted submission can make a form e-mail an unrelated
file from wp-content. There is no fixed release. As of 12 November 2026
WPScan lists "No known fix", and the plugin page on wordpress.org says it was
closed on 6 October 2026.

This file does not change the addon's files. It loads before all normal
plugins, then checks for each known problem whether it is still present on
the site, and acts only where it is.

Problems checked:

* CVE-2026-104246 - Contact Form 7 Signature Addon 4.2.2 and older.
  Action: the patch is applied.
* CVE-2026-94589 - Extensions For CF7 (HT Plugins) older than 3.4.6.
  Action: a warning to update to 3.4.6. No patch.
* CVE-2026-25863 - Conditional Fields for Contact Form 7 older than 2.7.3.
  Action: a warning to update to 2.7.3. No patch.

CVE-2026-94589 belongs to the HT Plugins plugin. It is not in Conditional
Fields for Contact Form 7 and not in the Breizhtorm addon.

How the patch for CVE-2026-104246 works:

1. The addon's two mail handlers are unhooked and replaced by hardened ones.
   Attachments come only from a server-side list of the files written during
   the current request, never from a posted value.
2. A signature field may hold only a real PNG data URI or nothing. Anything
   else fails validation and is blanked before other code sees it. This also
   covers a field inside a hidden Conditional Fields group, where validation
   is skipped. Limits: 2 MB and 10,000 x 10,000 px per signature.
3. Only the form's own signature fields are processed. The "inline" and
   "attachment" options are read from the form configuration, not from the
   request. Stored signature files get a random token in their name.
4. Any attachment on an outgoing Contact Form 7 e-mail that points through
   the signatures folder to somewhere else is dropped.

Layers 2 and 4 keep working even if the addon's handlers cannot be unhooked.

== Installation ==

1. Upload cf7-security-patches.php to wp-content/mu-plugins/. Create the
   folder if it does not exist. There is nothing to activate.
2. Leave Contact Form 7 Signature Addon active and unchanged.
3. Open Tools > CF7 Security Patches. The CVE-2026-104246 row must read
   "Present - patched".
4. Send a test form with a signature and check the e-mail.

A must-use plugin cannot be installed from Plugins > Add New.

To switch it off without deleting the file, add to wp-config.php:

    define( 'CF7_SECURITY_PATCHES_DISABLED', true );

The site is exposed again while that line is there. To remove the patch,
delete the file.

== Frequently Asked Questions ==

= What do the statuses on the status page mean? =

* Not relevant - the plugin is not active. Nothing is done.
* Not present - the plugin is active in a fixed version, or the flawed code
  was not found. Nothing is done.
* Present - patched - the problem is present and the patch is fully applied.
* Present - partly patched - the addon's handlers could not be replaced.
  Crafted values are still blocked; the other hardening is not in effect.
* Present - NOT patched - the patch was switched off in wp-config.php.
* Present - update needed - update that plugin to its fixed version.

= Will my security scanner stop reporting the addon? =

No. Scanners compare version numbers, and the addon's files are unchanged at
4.2.2.

= Does anything change for my forms? =

A signature in the mail body, a signature as an attachment, and the
"attachment" and "inline" options keep working. New signature files have
longer names. A signature field that receives something other than a drawing
is rejected and the form is not sent.

= What does it not do? =

* It was tested on a test install, not on your site.
* It protects only while the file is in place and the off switch is not set.
* Signature files stored before the patch keep their guessable names and
  stay publicly reachable. Signature files are never deleted automatically.
* Other plugins were not audited. For Conditional Fields for Contact Form 7
  and Extensions For CF7 it checks a version number only.
* Addon versions older than 4.2.2 were not tested.

= What was it tested with? =

WordPress 7.1.4, Contact Form 7 6.2.5, Conditional Fields for Contact Form 7
2.8.6, Contact Form 7 Signature Addon 4.2.2, PHP 8.3. 81 automated checks
passed on version 1.0.1.

== Changelog ==

= 1.0.1 =
* Disclaimer added to the file header, the plugin description and the status
  page. No functional change.

= 1.0.0 =
* First version.

== Credits ==

Contact Form 7 Signature Addon is by Breizhtorm (GPL-2.0). This project does
not include or redistribute it and is not affiliated with its authors.
WPScan credits Kiran Krishnakumar as the researcher who reported
CVE-2026-104246.

SHA-256 of cf7-security-patches.php 1.0.1:
dc88254c5ec7545660ae9b08674b1baff355ff03661197612dd8a86d70108f49
