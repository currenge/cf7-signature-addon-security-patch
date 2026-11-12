<?php
/**
 * Plugin Name:       CF7 Security Patches (Signature Addon CVE-2026-104246)
 * Description:       Must-use plugin. Loads before all other plugins, then checks for each known problem whether it is still present on this site, and acts only where it is. Patches "Contact Form 7 Signature Addon" 4.2.2 by Breizhtorm (CVE-2026-104246, no official fix), including forms that use Conditional Fields groups. Also checks "Extensions For CF7" (CVE-2026-94589) and "Conditional Fields for Contact Form 7" (CVE-2026-25863) and warns if an affected version is active. Status: Tools > CF7 Security Patches. Unofficial; does not modify other plugins' files. Provided "as is", without warranty of any kind: use at your own risk.
 * Version:           1.0.1
 * Requires at least: 5.0
 * Requires PHP:      5.6
 * Author:            Custom site patch (unofficial, not affiliated with the plugin authors)
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       cf7-security-patches
 * Update URI:        false
 *
 * DISCLAIMER - USE AT YOUR OWN RISK
 * ---------------------------------
 * This is an unofficial, independent patch. It is not written, reviewed or
 * endorsed by the authors of the plugins it relates to, by the Contact Form 7
 * project or by WordPress.org.
 *
 * It is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express or implied,
 * including but not limited to the warranties of merchantability and fitness
 * for a particular purpose (see sections 11 and 12 of the GNU General Public
 * License). You install and use it entirely at your own risk and on your own
 * responsibility. In no event are the authors liable for any claim, damage,
 * data loss or other liability arising from its use.
 *
 * Test it on a staging copy of your site and keep a backup before using it in
 * production. It reduces the specific risk described below; it does not make a
 * site secure, and it is not a substitute for an official fix or for replacing
 * an unmaintained plugin.
 *
 * CHANGELOG
 * ---------
 * 1.0.1  Disclaimer added to this header, the plugin description and the status
 *        page. No functional change.
 * 1.0.0  First version.
 *
 * INSTALL
 * -------
 * Copy this single file to wp-content/mu-plugins/ (create the folder if it does
 * not exist). There is nothing to activate. It is listed under
 * Plugins > Must-Use, and reports what it found under Tools > CF7 Security Patches.
 *
 * To switch it off without deleting the file, add to wp-config.php:
 *     define( 'CF7_SECURITY_PATCHES_DISABLED', true );
 *
 * HOW IT WORKS
 * ------------
 * Must-use plugins are loaded before normal plugins. This file therefore only
 * registers itself and waits. Once every plugin has loaded it runs one check per
 * problem ("is this still present here?") and applies a patch only for a problem
 * that is present. A plugin that is not installed, or has been updated to a
 * fixed version, is left completely alone.
 *
 * PROBLEMS CHECKED
 * ----------------
 * 1. CVE-2026-104246 - Contact Form 7 Signature Addon <= 4.2.2 (no official fix).
 *    The addon builds an e-mail attachment path out of the value posted in a
 *    signature field, so a visitor can make a form e-mail a file from wp-content
 *    that has nothing to do with signatures. With Conditional Fields the crafted
 *    value can also be sent in a field declared "hidden", which skips validation.
 *    ACTION: patched here (see CF7SecPatches_Signature below).
 *
 * 2. CVE-2026-94589 - Extensions For CF7 (Contact form 7 Database, Conditional
 *    Fields and Redirection) by HT Plugins <= 3.4.5. Fixed by its author in 3.4.6.
 *    This is a different plugin from the two above.
 *    ACTION: warning only - the fix is to update that plugin.
 *
 * 3. CVE-2026-25863 - Conditional Fields for Contact Form 7 < 2.7.3. Fixed by its
 *    author in 2.7.3.
 *    ACTION: warning only - the fix is to update that plugin.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'CF7SecPatches', false ) ) :

	define( 'CF7SECPATCHES_VERSION', '1.0.1' );

	/**
	 * Detection and reporting. Decides, per problem, whether anything has to be done.
	 */
	final class CF7SecPatches {

		/** Last Signature Addon release known to be affected (there is no fixed one). */
		const SIGNATURE_LAST_AFFECTED = '4.2.2';

		/** First fixed releases of the other two plugins. */
		const EXTCF7_FIXED_IN = '3.4.6';
		const CF7CF_FIXED_IN  = '2.7.3';

		/** @var CF7SecPatches|null */
		private static $instance = null;

		/** @var array[] One entry per problem, filled by run(). */
		private $report = array();

		/** @var CF7SecPatches_Signature|null Set only when the signature patch is applied. */
		private $signature_patch = null;

		public static function instance() {
			if ( null === self::$instance ) {
				self::$instance = new self();
			}

			return self::$instance;
		}

		private function __construct() {
			// Wait until every plugin is loaded, then look at what is really there.
			add_action( 'plugins_loaded', array( $this, 'run' ), 20 );
			add_action( 'admin_menu', array( $this, 'admin_menu' ) );
			add_action( 'admin_notices', array( $this, 'admin_notices' ) );
		}

		public function get_report() {
			return $this->report;
		}

		public function get_signature_patch() {
			return $this->signature_patch;
		}

		private function is_disabled() {
			return defined( 'CF7_SECURITY_PATCHES_DISABLED' ) && CF7_SECURITY_PATCHES_DISABLED;
		}

		public function run() {
			$this->report = array(
				$this->check_signature_addon(),
				$this->check_extensions_for_cf7(),
				$this->check_conditional_fields(),
			);
		}

		/* ------------------------------------------------------------------
		 * Problem 1: Signature Addon, CVE-2026-104246
		 * ---------------------------------------------------------------- */

		private function check_signature_addon() {
			$entry = array(
				'id'        => 'CVE-2026-104246',
				'plugin'    => 'Contact Form 7 Signature Addon',
				'problem'   => 'A crafted signature value makes a form e-mail an unrelated file from wp-content (path traversal in attachments).',
				'affected'  => '4.2.2 and older. No official fix.',
				'installed' => 'not active',
				'present'   => false,
				'state'     => 'not-installed',
				'action'    => 'Nothing to do.',
			);

			$loaded = defined( 'WPCF7_SIGNATURE_VERSION' ) || class_exists( 'Wpcf7_Signature_Mail', false );

			if ( ! $loaded ) {
				return $entry;
			}

			$version            = defined( 'WPCF7_SIGNATURE_VERSION' ) ? (string) WPCF7_SIGNATURE_VERSION : '';
			$entry['installed'] = '' !== $version ? $version : 'unknown version';

			if ( ! defined( 'WPCF7_VERSION' ) ) {
				$entry['action'] = 'Contact Form 7 is not active, so the addon cannot process any form. Nothing to do.';
				return $entry;
			}

			$in_affected_range = '' !== $version && version_compare( $version, self::SIGNATURE_LAST_AFFECTED, '<=' );

			// An affected version number settles it. The installed code is only
			// inspected when the number does not (or, in the admin, to report it).
			$code = ( $in_affected_range && ! is_admin() ) ? 'not-checked' : $this->signature_code_state();

			if ( $in_affected_range ) {
				$present = true;
				$why     = 'Version ' . $version . ' is in the affected range.';
			} elseif ( 'vulnerable' === $code ) {
				$present = true;
				$why     = 'The vulnerable code is still in Wpcf7_Signature_Mail::modify_components().';
			} elseif ( 'clean' === $code ) {
				$present = false;
				$why     = 'Version ' . $entry['installed'] . ' is newer than ' . self::SIGNATURE_LAST_AFFECTED . ' and the vulnerable code was not found.';
			} else {
				// Cannot tell: stay on the safe side.
				$present = true;
				$why     = 'This version could not be verified, so it is treated as affected.';
			}

			if ( $in_affected_range && 'vulnerable' === $code ) {
				$why .= ' Vulnerable code confirmed in the installed files.';
			}

			$entry['present'] = $present;

			if ( ! $present ) {
				$entry['state']  = 'not-present';
				$entry['action'] = $why . ' Patch not applied. This must-use plugin is no longer needed for this problem.';
				return $entry;
			}

			if ( $this->is_disabled() ) {
				$entry['state']  = 'disabled';
				$entry['action'] = $why . ' NOT PATCHED: switched off by CF7_SECURITY_PATCHES_DISABLED.';
				return $entry;
			}

			$this->signature_patch = new CF7SecPatches_Signature();

			if ( 'active' === $this->signature_patch->apply() ) {
				$entry['state']  = 'patched';
				$entry['action'] = $why . ' PATCHED: the addon\'s mail handlers are replaced by hardened ones. Forms using Conditional Fields groups are covered.';
			} else {
				$entry['state']  = 'partial';
				$entry['action'] = $why . ' PARTLY PATCHED: the addon\'s handlers could not be replaced. Crafted signature values are still blocked, the remaining hardening is not in effect.';
			}

			return $entry;
		}

		/**
		 * Look at the code the addon actually loaded: does it still build the
		 * attachment path from the posted value?
		 *
		 * @return string vulnerable | clean | unknown
		 */
		private function signature_code_state() {
			if ( ! class_exists( 'Wpcf7_Signature_Mail', false ) || ! method_exists( 'Wpcf7_Signature_Mail', 'modify_components' ) ) {
				return 'unknown';
			}

			try {
				$method = new ReflectionMethod( 'Wpcf7_Signature_Mail', 'modify_components' );
				$file   = $method->getFileName();

				if ( ! $file || ! is_readable( $file ) ) {
					return 'unknown';
				}

				// Remembered per file version, so the file is read once, not on every request.
				$key    = md5( $file . '|' . filemtime( $file ) . '|' . filesize( $file ) );
				$cached = get_option( 'cf7secpatches_sigcode' );

				if ( is_array( $cached ) && isset( $cached['key'], $cached['state'] ) && $cached['key'] === $key ) {
					return $cached['state'];
				}

				$lines  = file( $file );
				$source = implode( '', array_slice( $lines, $method->getStartLine() - 1, $method->getEndLine() - $method->getStartLine() + 1 ) );
			} catch ( Exception $e ) {
				return 'unknown';
			}

			$reads_posted_value = (bool) preg_match( '/get_posted_data\s*\(/', $source );
			$path_from_value    = ( false !== strpos( $source, 'explode' ) && false !== strpos( $source, 'wpcf7_signatures/' ) )
				|| (bool) preg_match( '/file_exists\s*\(\s*\$data\s*\)/', $source );

			$state = ( $reads_posted_value && $path_from_value ) ? 'vulnerable' : 'clean';

			update_option( 'cf7secpatches_sigcode', array( 'key' => $key, 'state' => $state ), true );

			return $state;
		}

		/* ------------------------------------------------------------------
		 * Problem 2: Extensions For CF7 (HT Plugins), CVE-2026-94589
		 * ---------------------------------------------------------------- */

		private function check_extensions_for_cf7() {
			$entry = array(
				'id'        => 'CVE-2026-94589',
				'plugin'    => 'Extensions For CF7 (Contact form 7 Database, Conditional Fields and Redirection)',
				'problem'   => 'Unauthenticated file upload through its signature field, which can lead to code execution.',
				'affected'  => '3.4.5 and older. Fixed in ' . self::EXTCF7_FIXED_IN . '.',
				'installed' => 'not active',
				'present'   => false,
				'state'     => 'not-installed',
				'action'    => 'Nothing to do.',
			);

			$version = $this->active_plugin_version( 'extensions-for-cf7' );

			return $this->judge_by_version( $entry, $version, self::EXTCF7_FIXED_IN );
		}

		/* ------------------------------------------------------------------
		 * Problem 3: Conditional Fields for Contact Form 7, CVE-2026-25863
		 * ---------------------------------------------------------------- */

		private function check_conditional_fields() {
			$entry = array(
				'id'        => 'CVE-2026-25863',
				'plugin'    => 'Conditional Fields for Contact Form 7',
				'problem'   => 'Unauthenticated denial of service through an unchecked repeat count.',
				'affected'  => 'Older than ' . self::CF7CF_FIXED_IN . '. Fixed in ' . self::CF7CF_FIXED_IN . '.',
				'installed' => 'not active',
				'present'   => false,
				'state'     => 'not-installed',
				'action'    => 'Nothing to do.',
			);

			$version = defined( 'WPCF7CF_VERSION' ) ? (string) WPCF7CF_VERSION : null;

			if ( null === $version ) {
				$version = $this->active_plugin_version( 'cf7-conditional-fields' );
			}

			return $this->judge_by_version( $entry, $version, self::CF7CF_FIXED_IN );
		}

		/**
		 * For a problem its own author has fixed: present only below the fixed
		 * version, and the action is a warning to update.
		 */
		private function judge_by_version( $entry, $version, $fixed_in ) {
			if ( null === $version ) {
				return $entry;
			}

			$entry['installed'] = '' !== $version ? $version : 'unknown version';

			if ( '' !== $version && version_compare( $version, $fixed_in, '>=' ) ) {
				$entry['state']  = 'not-present';
				$entry['action'] = 'Version ' . $version . ' already contains the author\'s fix. Nothing to do.';
				return $entry;
			}

			$entry['present'] = true;
			$entry['state']   = 'update-required';
			$entry['action']  = 'ACTION NEEDED: update this plugin to ' . $fixed_in . ' or later. This must-use plugin only warns about it and does not patch it.';

			return $entry;
		}

		/**
		 * Version of an active plugin, found by its folder name.
		 *
		 * @return string|null Null when no active plugin lives in that folder.
		 */
		private function active_plugin_version( $folder ) {
			$files = function_exists( 'wp_get_active_and_valid_plugins' ) ? (array) wp_get_active_and_valid_plugins() : array();

			if ( is_multisite() && function_exists( 'wp_get_active_network_plugins' ) ) {
				$files = array_merge( $files, (array) wp_get_active_network_plugins() );
			}

			foreach ( $files as $file ) {
				if ( basename( dirname( $file ) ) !== $folder ) {
					continue;
				}

				$data = get_file_data( $file, array( 'Version' => 'Version' ) );

				return isset( $data['Version'] ) ? (string) $data['Version'] : '';
			}

			return null;
		}

		/* ------------------------------------------------------------------
		 * Admin: Tools > CF7 Security Patches, and a notice when action is needed
		 * ---------------------------------------------------------------- */

		public function admin_menu() {
			add_management_page(
				'CF7 Security Patches',
				'CF7 Security Patches',
				'manage_options',
				'cf7-security-patches',
				array( $this, 'render_page' )
			);
		}

		private function state_label( $state ) {
			$labels = array(
				'not-installed'   => 'Not relevant',
				'not-present'     => 'Not present',
				'patched'         => 'Present - patched',
				'partial'         => 'Present - partly patched',
				'disabled'        => 'Present - NOT patched',
				'update-required' => 'Present - update needed',
			);

			return isset( $labels[ $state ] ) ? $labels[ $state ] : $state;
		}

		public function render_page() {
			if ( ! current_user_can( 'manage_options' ) ) {
				return;
			}

			echo '<div class="wrap"><h1>CF7 Security Patches</h1>';
			echo '<p>Must-use plugin, version ' . esc_html( CF7SECPATCHES_VERSION ) . '. Unofficial site patch. ';
			echo 'Each row is one known problem: whether it is still present on this site right now, and what is done about it.</p>';
			echo '<table class="widefat striped"><thead><tr>';

			foreach ( array( 'Problem', 'Plugin', 'Affected versions', 'Installed here', 'Still present?', 'What is done' ) as $heading ) {
				echo '<th>' . esc_html( $heading ) . '</th>';
			}

			echo '</tr></thead><tbody>';

			foreach ( $this->report as $entry ) {
				echo '<tr>';
				echo '<td><strong>' . esc_html( $entry['id'] ) . '</strong><br>' . esc_html( $entry['problem'] ) . '</td>';
				echo '<td>' . esc_html( $entry['plugin'] ) . '</td>';
				echo '<td>' . esc_html( $entry['affected'] ) . '</td>';
				echo '<td>' . esc_html( $entry['installed'] ) . '</td>';
				echo '<td><strong>' . esc_html( $this->state_label( $entry['state'] ) ) . '</strong></td>';
				echo '<td>' . esc_html( $entry['action'] ) . '</td>';
				echo '</tr>';
			}

			echo '</tbody></table>';
			echo '<p><strong>Use at your own risk.</strong> Unofficial patch, provided "as is" without warranty of any kind. ';
			echo 'It is not written or endorsed by the authors of the plugins listed above, and it is not a substitute for an official fix.</p>';
			echo '<p>File: <code>' . esc_html( wp_normalize_path( __FILE__ ) ) . '</code></p></div>';
		}

		public function admin_notices() {
			if ( ! current_user_can( 'manage_options' ) ) {
				return;
			}

			$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

			if ( ! $screen || ! in_array( $screen->id, array( 'plugins', 'dashboard', 'tools_page_cf7-security-patches' ), true ) ) {
				return;
			}

			foreach ( $this->report as $entry ) {
				if ( ! in_array( $entry['state'], array( 'partial', 'disabled', 'update-required' ), true ) ) {
					continue;
				}

				printf(
					'<div class="notice notice-error"><p><strong>CF7 Security Patches - %1$s, %2$s %3$s:</strong> %4$s</p></div>',
					esc_html( $entry['id'] ),
					esc_html( $entry['plugin'] ),
					esc_html( $entry['installed'] ),
					esc_html( $entry['action'] )
				);
			}
		}
	}

	/**
	 * The patch for CVE-2026-104246. Created and applied only when
	 * CF7SecPatches finds the problem present.
	 *
	 * 1. The addon's two mail handlers are unhooked and replaced by the hardened
	 *    versions below. Attachments are taken only from a server-side list of
	 *    the files written during the current request; nothing is derived from a
	 *    posted value.
	 * 2. A signature field may only contain a real PNG data URI (what the
	 *    signature pad produces) or nothing. Anything else fails validation and
	 *    is blanked before any other code can see it. The blanking does not
	 *    depend on validation, which Conditional Fields skips for hidden groups.
	 * 3. Only the form's own signature fields are processed, the "inline" and
	 *    "attachment" switches are read from the form configuration instead of
	 *    the request, and stored signature files get unguessable names.
	 * 4. A last check on the outgoing e-mail drops any attachment that points
	 *    through the signatures folder to somewhere else.
	 *
	 * Steps 2 and 4 keep working even if step 1 could not unhook the addon.
	 */
	final class CF7SecPatches_Signature {

		/** The only file names this patch creates or attaches. */
		const FILENAME_PATTERN = '/^[0-9A-Za-z_-]+\.png$/';

		const DATA_URI_PREFIX = 'data:image/png;base64,';

		/**
		 * Signature files written during this request: posted field name => absolute path.
		 * Only ever filled with paths generated on the server.
		 *
		 * @var array
		 */
		private $files = array();

		/**
		 * Value each processed field was replaced with (URL, path or data URI).
		 * Lets the posted-data filter run twice without rejecting its own output.
		 *
		 * @var array
		 */
		private $values = array();

		/**
		 * @return string active | partial
		 */
		public function apply() {
			$removed_data = 0;
			$removed_mail = 0;

			if ( apply_filters( 'cf7sigfix_replace_addon_handlers', true ) ) {
				$removed_data = $this->remove_addon_callback( 'wpcf7_posted_data', 'manage_signature_data' );
				$removed_mail = $this->remove_addon_callback( 'wpcf7_mail_components', 'modify_components' );
			}

			// Priority 9 / 11: before and after the addon's own priority 10, so the
			// protection also holds if its handlers could not be unhooked.
			add_filter( 'wpcf7_posted_data', array( $this, 'filter_posted_data' ), 9 );
			add_filter( 'wpcf7_mail_components', array( $this, 'filter_mail_components' ), 11, 3 );
			add_filter( 'wpcf7_validate_signature', array( $this, 'validate_signature' ), 9, 2 );
			add_filter( 'wpcf7_validate_signature*', array( $this, 'validate_signature' ), 9, 2 );

			return ( $removed_data > 0 && $removed_mail > 0 ) ? 'active' : 'partial';
		}

		/**
		 * Unhook a method of the addon's mail class from a filter.
		 *
		 * @return int Number of callbacks removed.
		 */
		private function remove_addon_callback( $hook, $method ) {
			global $wp_filter;

			if ( empty( $wp_filter[ $hook ] ) ) {
				return 0;
			}

			$callbacks = is_object( $wp_filter[ $hook ] ) ? $wp_filter[ $hook ]->callbacks : $wp_filter[ $hook ];
			$found     = array();

			foreach ( (array) $callbacks as $priority => $entries ) {
				foreach ( (array) $entries as $entry ) {
					$function = isset( $entry['function'] ) ? $entry['function'] : null;

					if (
						is_array( $function )
						&& isset( $function[0], $function[1] )
						&& is_object( $function[0] )
						&& $method === $function[1]
						&& is_a( $function[0], 'Wpcf7_Signature_Mail' )
					) {
						$found[] = array( $function, $priority );
					}
				}
			}

			$removed = 0;

			foreach ( $found as $item ) {
				if ( remove_filter( $hook, $item[0], $item[1] ) ) {
					$removed++;
				}
			}

			return $removed;
		}

		/* ------------------------------------------------------------------
		 * Posted data: validate, store, never pass raw input on
		 * ---------------------------------------------------------------- */

		/**
		 * Replacement for Wpcf7_Signature_Mail::manage_signature_data().
		 */
		public function filter_posted_data( $posted_data ) {
			if ( ! is_array( $posted_data ) ) {
				return $posted_data;
			}

			$tags = $this->signature_tags();

			if ( empty( $tags ) ) {
				return $posted_data;
			}

			$max_files = (int) apply_filters( 'cf7sigfix_max_signatures_per_submission', 20 );
			$stored    = 0;

			foreach ( array_keys( $posted_data ) as $key ) {
				$name = (string) $key;
				$tag  = $this->tag_for_key( $name, $tags );

				if ( ! $tag ) {
					continue; // Not a signature field of this form: left alone.
				}

				$data       = $posted_data[ $key ];
				$inline     = (bool) $tag->has_option( 'inline' );
				$attachment = (bool) $tag->has_option( 'attachment' );

				// The addon reads these two switches from the request. Pin them to
				// what the form is really configured to do.
				$posted_data[ $name . '-inline' ]     = $inline ? '1' : '';
				$posted_data[ $name . '-attachment' ] = $attachment ? '1' : '';

				// Already handled earlier in this request.
				if ( array_key_exists( $name, $this->values ) && $data === $this->values[ $name ] ) {
					continue;
				}

				$bytes = $this->decode_signature( $data );

				if ( false === $bytes || $stored >= $max_files ) {
					// Empty, or not a genuine signature image: nothing of the
					// posted value is allowed to travel further.
					$posted_data[ $key ] = '';
					unset( $this->files[ $name ], $this->values[ $name ] );
					continue;
				}

				$stored++;

				// Rebuilt from the decoded bytes, so it can only contain base64 characters.
				$value = self::DATA_URI_PREFIX . base64_encode( $bytes );

				if ( ! $inline ) {
					$path = $attachment
						? $this->store_as_temporary_file( $name, $bytes )
						: $this->store_in_signature_dir( $name, $bytes );

					if ( false !== $path ) {
						$this->files[ $name ] = $path;
						$value = $attachment ? $path : $this->signature_url( basename( $path ) );
					} else {
						error_log( 'CF7 Security Patches: cannot write the signature file for field "' . $name . '".' );
					}
				}

				$posted_data[ $key ]   = $value;
				$this->values[ $name ] = $value;
			}

			return $posted_data;
		}

		/**
		 * Decode a posted signature. Accepts only what the signature pad produces:
		 * a base64 PNG data URI of reasonable size.
		 *
		 * @param mixed $data Posted value.
		 * @return string|false Raw PNG bytes, or false.
		 */
		public function decode_signature( $data ) {
			if ( ! is_string( $data ) ) {
				return false;
			}

			$data          = trim( $data );
			$prefix_length = strlen( self::DATA_URI_PREFIX );

			if ( strlen( $data ) <= $prefix_length || 0 !== strncmp( $data, self::DATA_URI_PREFIX, $prefix_length ) ) {
				return false;
			}

			$max_bytes = (int) apply_filters( 'cf7sigfix_max_signature_bytes', 2 * 1024 * 1024 );
			$max_side  = (int) apply_filters( 'cf7sigfix_max_signature_side', 10000 );
			$encoded   = substr( $data, $prefix_length );

			if ( strlen( $encoded ) > 4 * ceil( $max_bytes / 3 ) + 64 ) {
				return false;
			}

			$encoded = str_replace( array( "\r", "\n", "\t" ), '', $encoded );
			$encoded = str_replace( ' ', '+', $encoded );
			$bytes   = base64_decode( $encoded, true );

			// 33 bytes = PNG signature + a complete IHDR chunk.
			if ( false === $bytes || strlen( $bytes ) < 33 || strlen( $bytes ) > $max_bytes ) {
				return false;
			}

			if ( "\x89PNG\r\n\x1a\n" !== substr( $bytes, 0, 8 ) || 'IHDR' !== substr( $bytes, 12, 4 ) ) {
				return false;
			}

			$size = unpack( 'Nwidth/Nheight', substr( $bytes, 16, 8 ) );

			if (
				! is_array( $size )
				|| $size['width'] < 1 || $size['height'] < 1
				|| $size['width'] > $max_side || $size['height'] > $max_side
			) {
				return false;
			}

			if ( function_exists( 'getimagesizefromstring' ) ) {
				$info = @getimagesizefromstring( $bytes );

				if ( ! is_array( $info ) || ! isset( $info[2] ) || IMAGETYPE_PNG !== $info[2] ) {
					return false;
				}
			}

			return $bytes;
		}

		/**
		 * Default mode: the image is stored in the public signatures folder and
		 * the posted value becomes its URL.
		 *
		 * @return string|false Absolute path of the new file.
		 */
		private function store_in_signature_dir( $name, $bytes ) {
			$dir = $this->signature_dir();

			if ( ! file_exists( $dir ) ) {
				if ( ! wp_mkdir_p( $dir ) ) {
					return false;
				}

				// Same access rules the addon writes when it creates the folder.
				$htaccess = trailingslashit( $dir ) . '.htaccess';

				if ( ! file_exists( $htaccess ) ) {
					@file_put_contents(
						$htaccess,
						'Order deny,allow' . "\n"
						. 'Deny from all' . "\n"
						. '<Files ~ "^[0-9A-Za-z_-]+\\.(png)$">' . "\n"
						. '    Allow from all' . "\n"
						. '</Files>' . "\n"
					);
				}
			}

			// Keeps the folder from being listed where .htaccess is not honoured.
			$index = trailingslashit( $dir ) . 'index.html';

			if ( ! file_exists( $index ) ) {
				@file_put_contents( $index, '' );
			}

			return $this->write_new_file( $dir, $this->new_filename( $name ), $bytes, 0644 );
		}

		/**
		 * "attachment" option: the image goes to Contact Form 7's protected
		 * temporary upload folder and the posted value becomes its path.
		 *
		 * @return string|false Absolute path of the new file.
		 */
		private function store_as_temporary_file( $name, $bytes ) {
			if ( ! function_exists( 'wpcf7_upload_tmp_dir' ) || ! function_exists( 'wpcf7_maybe_add_random_dir' ) ) {
				return false;
			}

			if ( function_exists( 'wpcf7_init_uploads' ) ) {
				wpcf7_init_uploads(); // Confirm upload dir.
			}

			$dir = wpcf7_maybe_add_random_dir( wpcf7_upload_tmp_dir() );

			// Only readable by the owner process, like Contact Form 7's own uploads.
			return $this->write_new_file( $dir, $this->new_filename( $name ), $bytes, 0400 );
		}

		private function write_new_file( $dir, $filename, $bytes, $mode ) {
			if ( ! is_dir( $dir ) ) {
				return false;
			}

			$filename = wp_unique_filename( $dir, $filename );

			if ( ! preg_match( self::FILENAME_PATTERN, $filename ) ) {
				return false;
			}

			$path = wp_normalize_path( trailingslashit( $dir ) . $filename );

			// "x": create only, never write over or through something that exists.
			$handle = @fopen( $path, 'xb' );

			if ( ! $handle ) {
				return false;
			}

			$written = fwrite( $handle, $bytes );
			fclose( $handle );

			if ( strlen( $bytes ) !== $written ) {
				@unlink( $path );
				return false;
			}

			@chmod( $path, $mode );

			return $path;
		}

		/**
		 * field-name + time + random token, so stored signatures cannot be found
		 * by guessing (the addon used field-name + time only).
		 */
		private function new_filename( $name ) {
			$base = strtolower( preg_replace( '/[^0-9A-Za-z_-]+/', '-', (string) $name ) );
			$base = trim( substr( $base, 0, 60 ), '-' );

			if ( '' === $base ) {
				$base = 'signature';
			}

			$token = strtolower( wp_generate_password( 20, false, false ) );

			return $base . '-' . time() . '-' . $token . '.png';
		}

		/* ------------------------------------------------------------------
		 * Validation
		 * ---------------------------------------------------------------- */

		/**
		 * Refuse a submission whose signature field holds anything other than a
		 * signature image. (The "required" check stays with the addon.)
		 */
		public function validate_signature( $result, $tag ) {
			$tag = $this->to_tag( $tag );

			if ( ! $tag || '' === (string) $tag->name ) {
				return $result;
			}

			$name = $tag->name;

			if ( ! isset( $_POST[ $name ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				return $result;
			}

			$raw = wp_unslash( $_POST[ $name ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

			if ( is_string( $raw ) && ( '' === trim( $raw ) || false !== $this->decode_signature( $raw ) ) ) {
				return $result;
			}

			$message = __( 'The signature could not be read. Please clear the field and sign again.', 'cf7-security-patches' );

			if ( is_object( $result ) && method_exists( $result, 'invalidate' ) ) {
				$result->invalidate( $tag, $message );
			} elseif ( is_array( $result ) ) {
				$result['valid']           = false;
				$result['reason'][ $name ] = $message;
			}

			return $result;
		}

		/* ------------------------------------------------------------------
		 * Outgoing e-mail
		 * ---------------------------------------------------------------- */

		/**
		 * Replacement for Wpcf7_Signature_Mail::modify_components().
		 */
		public function filter_mail_components( $components, $contact_form = null, $mail = null ) {
			if ( ! is_array( $components ) ) {
				return $components;
			}

			$attachments = isset( $components['attachments'] ) ? (array) $components['attachments'] : array();

			// Safety net: nothing may be attached "through" the signatures folder
			// unless it really is a file inside that folder.
			$attachments = array_values( array_filter( $attachments, array( $this, 'keep_attachment' ) ) );

			if ( ! empty( $this->files ) ) {
				$listed = $this->fields_listed_as_attachments( $contact_form, $mail );

				foreach ( $this->files as $name => $path ) {
					if ( ! in_array( $name, $listed, true ) && ! in_array( $this->base_name( $name ), $listed, true ) ) {
						continue;
					}

					if ( ! $this->is_own_signature_file( $path ) ) {
						continue;
					}

					if ( ! $this->is_already_attached( $path, $attachments ) ) {
						$attachments[] = $path;
					}
				}
			}

			$components['attachments'] = $attachments;

			return $components;
		}

		/**
		 * @return bool False for a path that goes through the signatures folder
		 *              but does not resolve to a file inside it.
		 */
		public function keep_attachment( $attachment ) {
			if ( ! is_string( $attachment ) || '' === $attachment ) {
				return true;
			}

			$signature_dir = untrailingslashit( wp_normalize_path( $this->signature_dir() ) );
			$normalized    = wp_normalize_path( $attachment );

			if ( $normalized !== $signature_dir && 0 !== strpos( $normalized, $signature_dir . '/' ) ) {
				return true; // Has nothing to do with the signatures folder.
			}

			return $this->is_file_inside( $attachment, $signature_dir );
		}

		/**
		 * Names of the fields listed in the "File attachments" box of the mail
		 * template currently being composed.
		 *
		 * @return string[]
		 */
		private function fields_listed_as_attachments( $contact_form, $mail ) {
			if ( ! is_object( $mail ) && class_exists( 'WPCF7_Mail' ) && method_exists( 'WPCF7_Mail', 'get_current' ) ) {
				$mail = WPCF7_Mail::get_current();
			}

			if ( ! is_object( $contact_form ) ) {
				$contact_form = $this->current_form();
			}

			if ( ! is_object( $mail ) || ! is_object( $contact_form ) || ! method_exists( $mail, 'name' ) ) {
				return array();
			}

			$template = $contact_form->prop( $mail->name() );

			if ( ! is_array( $template ) || empty( $template['attachments'] ) || ! is_string( $template['attachments'] ) ) {
				return array();
			}

			if ( ! preg_match_all( '/\[\s*([^\]\s]+)\s*\]/', $template['attachments'], $matches ) ) {
				return array();
			}

			return $matches[1];
		}

		private function is_already_attached( $path, $attachments ) {
			$real = realpath( $path );

			foreach ( $attachments as $attachment ) {
				if ( ! is_string( $attachment ) ) {
					continue;
				}

				if ( $attachment === $path || ( false !== $real && realpath( $attachment ) === $real ) ) {
					return true;
				}
			}

			return false;
		}

		/**
		 * True only for a file this patch can have written: strict name, and
		 * really located in the signatures folder or in CF7's temporary folder.
		 */
		private function is_own_signature_file( $path ) {
			if ( ! is_string( $path ) || ! preg_match( self::FILENAME_PATTERN, basename( $path ) ) ) {
				return false;
			}

			if ( $this->is_file_inside( $path, $this->signature_dir() ) ) {
				return true;
			}

			return function_exists( 'wpcf7_upload_tmp_dir' ) && $this->is_file_inside( $path, wpcf7_upload_tmp_dir() );
		}

		private function is_file_inside( $path, $dir ) {
			$real_path = realpath( $path );
			$real_dir  = realpath( $dir );

			if ( false === $real_path || false === $real_dir || ! is_file( $real_path ) ) {
				return false;
			}

			return 0 === strpos( wp_normalize_path( $real_path ), trailingslashit( wp_normalize_path( $real_dir ) ) );
		}

		/* ------------------------------------------------------------------
		 * Helpers
		 * ---------------------------------------------------------------- */

		private function current_form() {
			if ( function_exists( 'wpcf7_get_current_contact_form' ) ) {
				$form = wpcf7_get_current_contact_form();

				if ( $form ) {
					return $form;
				}
			}

			if ( class_exists( 'WPCF7_Submission' ) ) {
				$submission = WPCF7_Submission::get_instance();

				if ( $submission && method_exists( $submission, 'get_contact_form' ) ) {
					return $submission->get_contact_form();
				}
			}

			return null;
		}

		private function to_tag( $tag ) {
			if ( ! class_exists( 'WPCF7_FormTag' ) ) {
				return null;
			}

			return ( $tag instanceof WPCF7_FormTag ) ? $tag : new WPCF7_FormTag( $tag );
		}

		/**
		 * Signature fields of the form being submitted: name => tag.
		 *
		 * @return array
		 */
		private function signature_tags() {
			$form = $this->current_form();

			if ( ! is_object( $form ) || ! method_exists( $form, 'scan_form_tags' ) ) {
				return array();
			}

			$tags = array();

			foreach ( (array) $form->scan_form_tags() as $tag ) {
				$tag = $this->to_tag( $tag );

				if ( ! $tag || '' === (string) $tag->name || 'signature' !== rtrim( (string) $tag->type, '*' ) ) {
					continue;
				}

				if ( ! isset( $tags[ $tag->name ] ) ) {
					$tags[ $tag->name ] = $tag;
				}
			}

			return $tags;
		}

		/**
		 * Repeater add-ons post repeated fields as name__1, name__2, ...
		 */
		private function base_name( $name ) {
			return preg_replace( '/(__[0-9]+)+$/', '', (string) $name );
		}

		private function tag_for_key( $name, $tags ) {
			if ( isset( $tags[ $name ] ) ) {
				return $tags[ $name ];
			}

			$base = $this->base_name( $name );

			return ( $base !== $name && isset( $tags[ $base ] ) ) ? $tags[ $base ] : null;
		}

		/** Same location, constants and filter as the addon. */
		private function signature_dir() {
			if ( defined( 'WPCF7_SIGNATURE_DIR' ) ) {
				return WPCF7_SIGNATURE_DIR;
			}

			return wpcf7_upload_dir( 'dir' ) . '/wpcf7_signatures';
		}

		private function signature_dir_url() {
			if ( defined( 'WPCF7_SIGNATURE_URL' ) ) {
				return WPCF7_SIGNATURE_URL;
			}

			return wpcf7_upload_dir( 'url' ) . '/wpcf7_signatures';
		}

		private function signature_url( $filename ) {
			$url = trailingslashit( $this->signature_dir_url() ) . $filename;

			if ( is_ssl() && 'http:' === substr( $url, 0, 5 ) ) {
				$url = 'https:' . substr( $url, 5 );
			}

			return apply_filters( 'wpcf7_signature_url', esc_url_raw( $url ) );
		}
	}

	CF7SecPatches::instance();

endif;
