<?php
/*
 * fips-unbound-custom.php - add or remove the FIPS .fips forward-zone in
 * the pfSense DNS Resolver "Custom options" box.
 *
 * pfSense stores that box base64-encoded at unbound/custom_options in
 * config.xml and splices it into the generated /var/unbound/unbound.conf
 * verbatim (see unbound_generate_config() in /etc/inc/unbound.inc). It
 * is the only operator-writable surface in that file: every include:
 * unbound.inc emits names a specific generated file, and there is no
 * conf.d directory to drop into.
 *
 * The box belongs to the operator, who may well have their own lines in
 * it, so this only ever touches the text between its own markers and
 * leaves the rest byte-for-byte alone.
 *
 * Usage:
 *   fips-unbound-custom.php add     # snippet on stdin
 *   fips-unbound-custom.php remove
 *
 * Invoked by fips-dns-setup and fips-dns-teardown; see
 * packaging/pfsense/README.md.
 */

/* Under FIPS_UNBOUND_HELPER_TEST the file only defines its functions, so
 * fips_strip_block() can be unit-tested where pfSense's includes do not
 * exist. Everything that touches config.xml stays below that guard. */
if (!getenv('FIPS_UNBOUND_HELPER_TEST')) {
	require_once("config.inc");
	require_once("util.inc");
	require_once("unbound.inc");
}

define('FIPS_BEGIN', '# BEGIN FIPS - managed by fips-dns-setup, do not edit this block');
define('FIPS_END', '# END FIPS');

function fips_log($msg) {
	fwrite(STDERR, "fips-dns: {$msg}\n");
}

/* pfSense 2.8 uses the config_*_path() accessors; older branches only
 * have the $config global. Support both rather than pinning this script
 * to one branch of a firewall people upgrade in place. */
function fips_config_get_custom_options() {
	if (function_exists('config_get_path')) {
		return (string) config_get_path('unbound/custom_options', '');
	}
	global $config;
	return isset($config['unbound']['custom_options'])
		? (string) $config['unbound']['custom_options'] : '';
}

function fips_config_set_custom_options($value) {
	if (function_exists('config_set_path')) {
		config_set_path('unbound/custom_options', $value);
		return;
	}
	global $config;
	$config['unbound']['custom_options'] = $value;
}

function fips_resolver_enabled() {
	if (function_exists('config_path_enabled')) {
		return config_path_enabled('unbound');
	}
	global $config;
	return !empty($config['unbound']['enable']);
}

/* Drop any existing FIPS block, returning the operator's own text. A
 * partial block (someone deleted one marker by hand in the GUI) is left
 * alone and reported, because guessing where it ended would be as
 * likely to eat their configuration as to fix ours. */
function fips_strip_block($text, &$had_block, &$malformed) {
	$had_block = false;
	$malformed = false;

	$begin = strpos($text, FIPS_BEGIN);
	$end = strpos($text, FIPS_END);

	if ($begin === false && $end === false) {
		return $text;
	}
	if ($begin === false || $end === false || $end < $begin) {
		$malformed = true;
		return $text;
	}

	$had_block = true;
	/* Cut exactly what fips_add_block() inserted, and no operator text.
	 * fips_add_block puts a newline before BEGIN only when text precedes
	 * it, and a newline after END. Consume the trailing newline always,
	 * but the leading one only when nothing follows the block — otherwise
	 * removing it would splice the line before BEGIN onto the line after
	 * END (e.g. a comment above the block onto an option added below it).
	 * So an add-then-remove restores the original byte for byte, and text
	 * added after the block survives on its own line. */
	$stop = $end + strlen(FIPS_END);
	if (substr($text, $stop, 1) === "\n") {
		$stop += 1;
	}
	$tail = substr($text, $stop);
	$start = ($tail === '' && $begin > 0 && $text[$begin - 1] === "\n")
		? $begin - 1 : $begin;
	return substr($text, 0, $start) . $tail;
}

/* Append the FIPS block to the operator's text without altering it. */
function fips_add_block($text, $snippet) {
	$prefix = ($text === '') ? '' : "\n";
	return $text . $prefix . FIPS_BEGIN . "\n" . $snippet . "\n" . FIPS_END . "\n";
}

if (getenv('FIPS_UNBOUND_HELPER_TEST')) {
	return;
}

$action = isset($argv[1]) ? $argv[1] : '';
if ($action !== 'add' && $action !== 'remove') {
	fwrite(STDERR, "usage: {$argv[0]} add|remove\n");
	exit(1);
}

$existing = base64_decode(fips_config_get_custom_options(), true);
if ($existing === false) {
	fips_log("ERROR: unbound/custom_options in config.xml is not valid base64; refusing to touch it.");
	exit(1);
}

$had_block = false;
$malformed = false;
$operator_text = fips_strip_block($existing, $had_block, $malformed);

if ($malformed) {
	fips_log("ERROR: found only one of the FIPS begin/end markers in the DNS Resolver");
	fips_log("ERROR: custom options. Remove the partial block by hand in Services >");
	fips_log("ERROR: DNS Resolver > Custom options, then re-run this command.");
	exit(1);
}

if ($action === 'add') {
	$snippet = rtrim(stream_get_contents(STDIN), "\r\n");
	if ($snippet === '') {
		fips_log("ERROR: no snippet on stdin");
		exit(1);
	}
	$new = fips_add_block($operator_text, $snippet);
	$desc = $had_block
		? "fips: update .fips forward-zone in DNS Resolver custom options"
		: "fips: add .fips forward-zone to DNS Resolver custom options";
} else {
	if (!$had_block) {
		fips_log("no FIPS block in the DNS Resolver custom options; nothing to remove");
		exit(0);
	}
	$new = $operator_text;
	$desc = "fips: remove .fips forward-zone from DNS Resolver custom options";
}

if ($new === $existing) {
	fips_log("DNS Resolver custom options already match; leaving config.xml untouched");
	exit(0);
}

/* Validate the merged options the way the GUI does before saving them.
 * unbound.conf is generated wholesale from config.xml, so a merge that
 * does not parse would take DNS away from every client behind the
 * firewall on the restart below. test_unbound_config() renders the
 * candidate config into a scratch directory and runs unbound-checkconf
 * over it; guarded with function_exists like the other accessors, since
 * older branches do not have it. */
if (function_exists('test_unbound_config')) {
	$live = function_exists('config_get_path')
		? config_get_path('unbound', array())
		: (isset($config['unbound']) ? $config['unbound'] : array());
	if (!is_array($live)) {
		$live = array();
	}
	// Same shape as pfSense's own save path (services_unbound.php): merge
	// the candidate custom_options over the live unbound config and hand
	// it to test_unbound_config, which renders the full unbound.conf and
	// runs unbound-checkconf. It returns the checker's exit code, so a
	// NON-zero result is the failure — matching core, which does
	// `if (test_unbound_config(...)) { $input_errors[] = ... }`. (A
	// re-apply draws a benign "duplicate forward zone ... ignored"
	// warning from the test render; checkconf still exits 0, which is a
	// pass, exactly as it is for a forward-zone entered in the GUI box.)
	$candidate = array_merge($live, array(
		'custom_options' => ($new === '') ? '' : base64_encode($new),
	));
	$check_output = array();
	if (test_unbound_config($candidate, $check_output)) {
		fips_log("ERROR: the merged DNS Resolver custom options do not pass unbound-checkconf;");
		fips_log("ERROR: config.xml has NOT been modified. unbound-checkconf said:");
		foreach ((array) $check_output as $line) {
			fips_log("ERROR:     " . rtrim($line));
		}
		exit(1);
	}
}

fips_config_set_custom_options($new === '' ? '' : base64_encode($new));

/* write_config() records a config-history entry, so this edit is
 * revertable from Diagnostics > Backup & Restore > Config History. */
write_config($desc);

if (!fips_resolver_enabled()) {
	$addr = isset($argv[2]) ? $argv[2] : '<bind_addr>';
	$port = isset($argv[3]) ? $argv[3] : '<port>';
	fips_log("WARNING: the DNS Resolver (unbound) is not enabled, so the block just");
	fips_log("WARNING: written has no effect until it is. If this firewall uses the DNS");
	fips_log("WARNING: Forwarder (dnsmasq) instead, add this line under Services > DNS");
	fips_log("WARNING: Forwarder > Advanced Options and run fips-dns-teardown:");
	fips_log("WARNING:     server=/fips/{$addr}#{$port}");
	/* Distinct from success so the caller does not announce a working setup. */
	exit(3);
}

/* Regenerate /var/unbound/unbound.conf from config.xml and restart the
 * resolver. Nothing shorter works: the file is generated wholesale, so
 * a reload alone would re-read the config we have not rewritten yet. */
sync_unbound_service();

fips_log("DNS Resolver updated and restarted");
exit(0);
