<?php
/**
 * Client Media Vault — Client Authentication Forms Handler
 *
 * @package WordPress
 * @subpackage sms
 * @since 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CMV_Auth {

	private static $flash = [];

	public static function init() {
		add_action( 'template_redirect', [ __CLASS__, 'redirect_logged_in_clients' ] );
		add_action( 'init',              [ __CLASS__, 'handle_login' ] );
		add_action( 'init',              [ __CLASS__, 'handle_logout' ] );
		add_action( 'init',              [ __CLASS__, 'handle_forgot_password' ] );
		add_action( 'init',              [ __CLASS__, 'handle_reset_password' ] );
	}

	/* ══════════════════════════════════════════════════════════
	   REDIRECT logged-in clients away from wp-login.php
	   ══════════════════════════════════════════════════════════ */

	public static function redirect_logged_in_clients() {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! in_array( 'client', (array) $user->roles ) ) {
			return;
		}
		if ( is_page( 'client-login' ) ) {
			wp_safe_redirect( self::page_url( 'client-media-vault' ) );
			exit;
		}
	}

	public static function handle_login() {

	if ( empty( $_POST['cmv_login_nonce'] ) ) {
		return;
	}

	if ( ! wp_verify_nonce( $_POST['cmv_login_nonce'], 'cmv_login' ) ) {
		return;
	}

	$username = sanitize_user( wp_unslash( $_POST['username'] ?? '' ) );
	$password = $_POST['password'] ?? '';
	$remember = ! empty( $_POST['remember'] );

	// validation
	if ( $username === '' || $password === '' ) {
		self::set_message( 'error', __( 'Please enter username and password.', 'sms' ) );
		return;
	}

	$user = wp_signon([
		'user_login'    => $username,
		'user_password' => $password,
		'remember'      => $remember,
	], is_ssl() );

	if ( is_wp_error( $user ) ) {
		self::set_message( 'error', __( 'Invalid username or password.', 'sms' ) );
		return;
	}

	wp_safe_redirect( self::page_url( 'client-media-vault' ) );
	exit;
}

	/* ══════════════════════════════════════════════════════════
	   LOGOUT handler
	   ══════════════════════════════════════════════════════════ */

	public static function handle_logout() {
		if ( ! isset( $_GET['cmv_action'] ) || $_GET['cmv_action'] !== 'logout' ) {
			return;
		}
		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'cmv_logout' ) ) {
			return;
		}
		wp_logout();
		wp_safe_redirect( self::page_url( 'client-login' ) );
		exit;
	}

	/* ══════════════════════════════════════════════════════════
	   FORGOT PASSWORD handler
	   ══════════════════════════════════════════════════════════ */

	public static function handle_forgot_password() {

		if ( empty( $_POST['cmv_forgot_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST['cmv_forgot_nonce'], 'cmv_forgot' ) ) {
			return;
		}


		$email = sanitize_email( wp_unslash( $_POST['cmv_email'] ?? '' ) );

		// Validation
		if ( $email === '' ) {
			self::set_message( 'error', __( 'Email is required.', 'sms' ) );
			return;
		}

		if ( ! is_email( $email ) ) {
			self::set_message( 'error', __( 'Please enter a valid email address.', 'sms' ) );
			return;
		}

		$user = get_user_by( 'email', $email );

		$generic = __( 'If that email exists, a reset link has been sent.', 'sms' );

		if ( ! $user ) {
			self::set_message( 'error', $generic );
			return;
		}

		$key = get_password_reset_key( $user );

		if ( is_wp_error( $key ) ) {
			self::set_message( 'error', __( 'Could not generate reset link.', 'sms' ) );
			return;
		}

		$reset_url = add_query_arg([
			'key'   => $key,
			'login' => rawurlencode( $user->user_login ),
		], self::page_url( 'reset-password' ) );

		wp_mail(
			$user->user_email,
			__( 'Password Reset', 'sms' ),
			sprintf(
				"Reset your password:\n\n%s\n\nThis link expires in 24 hours.",
				$reset_url
			)
		);

		self::set_message( 'success', $generic );
	}

	/* ══════════════════════════════════════════════════════════
	   RESET PASSWORD handler
	   ══════════════════════════════════════════════════════════ */

	public static function handle_reset_password() {

		if ( empty( $_POST['cmv_reset_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST['cmv_reset_nonce'], 'cmv_reset' ) ) {
			return;
		}

		$key   = sanitize_text_field( $_POST['cmv_key'] ?? '' );
		$login = sanitize_text_field( $_POST['cmv_login'] ?? '' );
		$pass1 = $_POST['cmv_pass1'] ?? '';
		$pass2 = $_POST['cmv_pass2'] ?? '';

		if ( $pass1 === '' || $pass1 !== $pass2 ) {
			self::set_message( 'error', __( 'Passwords do not match.', 'sms' ) );
			return;
		}

		if ( strlen( $pass1 ) < 8 ) {
			self::set_message( 'error', __( 'Password must be at least 8 characters.', 'sms' ) );
			return;
		}

		$user = check_password_reset_key( $key, $login );

		if ( is_wp_error( $user ) ) {
			self::set_message( 'error', __( 'Invalid or expired reset link.', 'sms' ) );
			return;
		}

		reset_password( $user, $pass1 );

		self::set_message( 'success', __( 'Password reset successful. You can now log in.', 'sms' ) );
	}

	public static function set_message($type, $message) {
		self::$flash = [
			'type'    => $type,
			'message' => $message
		];
	}
	
	public static function get_message() {
		return self::$flash;
	}

	public static function page_url( $slug ) {
		$page = get_page_by_path( $slug );
		return $page ? get_permalink( $page ) : home_url( '/' . $slug . '/' );
	}
}
function sms_cmv_page_url( $slug ) {
	return CMV_Auth::page_url( $slug );
}