<?php
/**
 * WordPress Coding Standard.
 *
 * @package WPCS\WordPressCodingStandards
 * @link	https://github.com/WordPress-Coding-Standards/WordPress-Coding-Standards
 * @license https://opensource.org/licenses/MIT MIT
 */

/**
 * WordPress_Sniffs_Theme_CorrectTGMPAVersionSniff.
 *
 * Verifies that if the TGM Plugin Activation library is included, the correct version is used.
 * - Check whether the version included is up to date.
 * - Check whether the version included is (most likely) downloaded via the Custom Generator with
 *	 the correct settings.
 *
 * @link    https://make.wordpress.org/themes/handbook/review/...... @todo
 *
 * @package WPCS\WordPressCodingStandards
 *
 * @since   0.xx.0
 */
class WordPress_Sniffs_Theme_CorrectTGMPAVersionSniff implements PHP_CodeSniffer_Sniff {

	const GITHUB_TGMPA_API_URL = 'https://api.github.com/repos/TGMPA/TGM-Plugin-Activation/releases/latest';

	const GITHUB_API_OAUTH_QUERY = '?access_token=%s';

	/**
	 * GitHub oAuth token.
	 *
	 * Intended to be set in the ruleset.
	 *
	 * This is to prevent issues with rate limiting if a lot of requests are made from the same server.
	 *
	 * "Normal" users generaly won't need to set this, but if the sniffs are run for all themes
	 * uploaded to wordpress.org, that IP address might run into the rate limit of 60 calls per hour.
	 * Setting a oauth token in the custom ruleset used will prevent this.
	 * Also usefull for people testing the sniffs and for running travis builds.
	 *
	 * Alternatively, the token can also be set via an environment key called `GITHUB_OAUTH_TOKEN`.
	 *
	 * @var string
	 */
	public $github_oauth_token = '';

	/**
	 * Whether or not an oAuth error was received when making the API call.
	 *
	 * @var bool
	 */
	private $oauth_error = false;

	/**
	 * Whether or not an rate limiting error was received when making the API call.
	 *
	 * @var bool
	 */
	private $rate_limit_error = false;

	/**
	 * Array of files which have already been checked.
	 *
	 * As we're checking for the TGMPA class in several different ways, it may be detected more
	 * than once for the same file. This parameter prevents the sniff throwing more than one
	 * message per check per file.
	 *
	 * @var array <string> => <bool>
	 */
	private $files_checked = array();

	/**
	 * Fall-back for the latest version number for if the API call failed.
	 *
	 * @var string
	 */
	private $current_version = '2.5.0';

	/**
	 * Returns an array of tokens this test wants to listen for.
	 *
	 * @return array
	 */
	public function register() {
		// Get the current version number for TGMPA from GitHub.
		$this->update_current_version();

		/*
		 * People sometimes inadvertently prefix the class or remove documentation, so check
		 * on a couple of different typical code snippets/tokens.
		 */
		return array(
			// Check for the file name (may have been changed).
			T_OPEN_TAG,

			// Check based on some typical code snippets.
			T_CLASS,
			T_CONST,
			T_FUNCTION,
			T_STRING,
		);
	}

	/**
	 * Processes this test, when one of its tokens is encountered.
	 *
	 * @param PHP_CodeSniffer_File $phpcsFile The file being scanned.
	 * @param int                  $stackPtr  The position of the current token
	 *                                        in the stack passed in $tokens.
	 *
	 * @return void
	 */
	public function process( PHP_CodeSniffer_File $phpcsFile, $stackPtr ) {
		if ( true === $this->oauth_error ) {
			$phpcsFile->addWarning(
				'The GITHUB_OAUTH_TOKEN you provided is invalid. Please update the token in your custom ruleset or environment properties.',
				0,
				'githubOauthTokenInvalid'
			);
			$this->oauth_error = false;
		}
		if ( true === $this->rate_limit_error ) {
			// @todo Add link to GH wiki page documenting the properties.
			$phpcsFile->addWarning(
				'You are running PHPCS more than 60 times per hour. You may want to consider setting the `github_oauth_token` property in your custom ruleset for Theme Review. For more information see: ... (GH wiki page).',
				0,
				'githubRateLimitReached'
			);
			$this->rate_limit_error = false;
		}

		$current_file = $this->get_scanned_file_name( $phpcsFile );

		// No need to check a file previously recognized as TGMPA more than once.
		if ( false !== $current_file && ( isset( $this->files_checked[ $current_file ] ) && true === $this->files_checked[ $current_file ] ) ) {
			return;
		}

		// If we don't recognize the file as TGMPA based on the current token, it doesn't mean it isn't,
		// so just return and let the next sniffed token come in.
		if ( false === $this->is_tgmpa_file( $phpcsFile, $stackPtr, $current_file ) ) {
			return;
		}

		/*
		 * Ok, we are in a file which contains code typical for TGMPA.
		 * Walk the doc block comments before the class declaration to find if this is the correct version.
		 * Normally this will be the first doc block encountered, so this is not as 'heavy' as it looks.
		 */
		$tokens 		   = $phpcsFile->getTokens();
		$next_doc_block	   = 0;
		$first_class_token = $phpcsFile->findNext( T_CLASS, 0 );

		while ( ( $next_doc_block = $phpcsFile->findNext( T_DOC_COMMENT_OPEN_TAG, ( $next_doc_block + 1 ), $first_class_token ) ) !== false ) {

			$tags = $this->get_docblock_tags( $phpcsFile, $next_doc_block );
			if ( empty( $tags ) ) {
				continue;
			}

			if ( isset( $tags['subpackage'] ) && 'Example' === $tags['subpackage'] ) {
				// Not the TGMPA class file doc block, but the example file doc block.
				// Some authors put both in the same file, so just move on.
				continue;
			}

			if ( ! isset( $tags['package'], $tags['version'] ) || 'TGM-Plugin-Activation' !== $tags['package'] ) {
				continue;
			}

			if ( preg_match( '`^([0-9\.]+(?:-(?:alpha|beta|RC)(?:[0-9])?)?)`', $tags['version'], $matches ) ) {

				$version = $matches[1];

				if ( true === version_compare( $this->current_version, $version, '>' ) ) {
					$error = 'Please upgrade the included version of the TGM plugin activation class to the latest version (%s). Found version: %s';
					$data  = array(
						$this->current_version,
						$version,
					);
					$phpcsFile->addError( $error, 0, 'upgradeRequired', $data );

					if ( true === version_compare( '2.5.0', $version, '>' ) ) {
						$error = 'There have been some minor changes to the TGMPA configuration options between version %s and the current version %s. Please verify your configuration arrays. For more information: http://tgmpluginactivation.com/configuration/';
						$data  = array(
							$version,
							$this->current_version,
						);
						$phpcsFile->addWarning( $error, 0, 'configurationOptions', $data );

					}
				} elseif ( true === version_compare( $this->current_version, $version, '<' ) ) {
					$error = 'Please do not use non-stable versions of the TGM plugin activation class. The current version is %s. Found version: %s';
					$data  = array(
						$this->current_version,
						$version,
					);
					$phpcsFile->addError( $error, 0, 'useStableVersion', $data );
				}
				unset( $matches, $error, $data );

				if ( 1 !== preg_match( '`^' . preg_quote( $version ) . '\s+for\s+(parent theme|child theme|plugin)\s+(.+?)\s+for publication on (WordPress\.org|ThemeForest)`', $tags['version'], $matches ) || 'WordPress.org' !== $matches[3] ) {
					$error = 'Your version of the TGM Plugin Activation class was not downloaded through the Custom TGMPA Generator. Please download a fresh copy and make sure you select "WordPress.org" as your publication channel to get the correct version of TGMPA. The Custom TGMPA Generator is located at http://tgmpluginactivation.com/download/';
					$phpcsFile->addError( $error, 0, 'wrongVersion' );

					/*
					 Potential other checks:
					 1. theme header vs parent/child theme
					 2. theme header theme name vs name - is this version generated afresh ?
					 */
				}
			}

			// Ok, the file was recognized as TGMPA and the relevant doc block checks performed,
			// no need to do it again for other sniffed tokens in this file.
			$this->files_checked[ $current_file ] = true;

			break;
		}

		// The file was recognized as TGMPA, but no valid file doc block for TGMPA was found.
		if ( ! isset( $this->files_checked[ $current_file ] ) || false === $this->files_checked[ $current_file ] ) {
			$error = 'TGMPA was detected in your theme, but the version could not be determined. Please ensure you use the latest stable release of the TGM Plugin Activation library (%s). Download a fresh copy now using the Custom TGMPA Generator at http://tgmpluginactivation.com/download/';
			$data  = array( $this->current_version );
			$phpcsFile->addError( $error, 0, 'versionUndetermined', $data );

			$this->files_checked[ $current_file ] = true;
		}
	}

	/**
	 * Get the file name of the current file being scanned.
	 *
	 * @param PHP_CodeSniffer_File $phpcsFile The file being scanned.
	 *
	 * @return string|false The file name or false if it could not be determined.
	 */
	protected function get_scanned_file_name( PHP_CodeSniffer_File $phpcsFile ) {
		$reflection = new ReflectionObject( $phpcsFile->phpcs );
		if ( true === $reflection->hasProperty( 'file' ) ) {
			$file_property = $reflection->getProperty( 'file' );
			$file_property->setAccessible( true );
			return $file_property->getValue( $phpcsFile->phpcs );
		}
		return false;
	}

	/**
	 * Try to determine whether this is the TGM Plugin Activation library file.
	 *
	 * @param PHP_CodeSniffer_File $phpcsFile The file being scanned.
	 * @param int                  $stackPtr  The position of the current token.
	 * @param string               $file_name The file name of the current file being sniffed.
	 *
	 * @return bool
	 */
	protected function is_tgmpa_file( PHP_CodeSniffer_File $phpcsFile, $stackPtr, $file_name ) {

		// First check based on filename.
		if ( false !== $file_name ) {
			$file_name = strtolower( basename( $file_name ) );
			if ( 'class-tgm-plugin-activation.php' === $file_name || 'tgm-plugin-activation.php' === $file_name ) {
				return true;
			}
		}

		// Otherwise, check for typical code snippets.
		$tokens = $phpcsFile->getTokens();
		$token	= $tokens[ $stackPtr ];

		if ( 'T_CLASS' === $token['type'] || 'T_FUNCTION' === $token['type'] ) {
			$name = $phpcsFile->getDeclarationName( $stackPtr );
			if ( ! empty( $name ) ) {
				if ( 'T_CLASS' === $token['type'] && 'TGM_Plugin_Activation' === $name ) {
					// Matched: `class TGM_Plugin_Activation`.
					return true;
				} elseif ( 'T_FUNCTION' === $token['type'] && 'tgmpa' === $name ) {
					// Matched: `function tgmpa`.
					return true;
				}
			}
			return false;
		}

		if ( 'T_CONST' === $token['type'] ) {
			$const_name_token = $phpcsFile->findNext( PHP_CodeSniffer_Tokens::$emptyTokens, ( $stackPtr + 1 ), null, true, null, true );
			if ( T_STRING === $tokens[ $const_name_token ]['code'] && 'TGMPA_VERSION' === $tokens[ $const_name_token ]['content'] ) {
				// Matched: `const TGMPA_VERSION`.
				return true;
			}
			return false;
		}

		if ( 'T_STRING' === $token['type'] ) {
			if ( 'do_action' === $token['content'] ) {
				// @todo - wait for utility functions.
				// Check if it's a function call.
				// Get the first parameter & strip_quotes()
				// Check if the first parameter is 'tgmpa_register'
				//
				// Matched: `do_action( 'tgmpa_register' )`.
			}
			return false;
		}

		return false;
	}

	/**
	 * Retrieve an array with the doc block tags from a T_DOC_COMMENT_OPEN_TAG.
	 *
	 * @param PHP_CodeSniffer_File $phpcsFile      The file being scanned.
	 * @param int                  $comment_opener The position of the comment opener.
	 *
	 * @return array
	 */
	protected function get_docblock_tags( PHP_CodeSniffer_File $phpcsFile, $comment_opener ) {
		$tokens = $phpcsFile->getTokens();
		$tags	= array();
		$opener = $tokens[ $comment_opener ];

		if ( ! isset( $opener['comment_tags'] ) ) {
			return $tags;
		}

		$closer = null;
		if ( isset( $opener['comment_closer'] ) ) {
			$closer = $opener['comment_closer'];
		}

		$tag_count = count( $opener['comment_tags'] );

		for ( $i = 0; $i < $tag_count; $i++ ) {
			$tag_token = $opener['comment_tags'][ $i ];
			$tag	   = trim( $tokens[ $tag_token ]['content'], '@' );

			$search_end = $closer;
			if ( ( $i + 1 ) < $tag_count ) {
				$search_end = $opener['comment_tags'][ ( $i + 1 ) ];
			}

			$value_token  = $phpcsFile->findNext( T_DOC_COMMENT_STRING, ( $tag_token + 1 ), $search_end );
			$tags[ $tag ] = trim( $tokens[ $value_token ]['content'] );
			unset( $tag_token, $tag, $search_end, $value );
		}

		return $tags;
	}

	/**
	 * Get the version number (tag_name) of the latest TGMPA release from the GitHub API.
	 */
	protected function update_current_version() {
		$api_url	 = self::GITHUB_TGMPA_API_URL;
		$oauth_token = $this->get_oauth_token();

		if ( false !== $oauth_token ) {
			$api_url .= sprintf( self::GITHUB_API_OAUTH_QUERY, $oauth_token );
		}

		$stream_options = array(
			'http' => array(
				'method'		   => 'GET',
				'user_agent'	   => 'WordPress-Coding-Standards/Theme-Review-Sniffs',
				'protocol_version' => 1.1,
			),
		);
		$stream_context = stream_context_create( $stream_options );
		$response		= file_get_contents( $api_url, false, $stream_context );
		$headers		= $this->parse_response_headers( $http_response_header );

		// Check for invalid oAuth token response.
		if ( 401 === $headers['response_code'] && false !== $oauth_token ) {
			$this->oauth_error = true;
			return;
		}

		// Check for rate limit error response.
		if ( 403 === $headers['response_code'] && '0' === $headers['X-RateLimit-Remaining'] ) {
			$this->rate_limit_error = true;
			return;
		}

		if ( 200 !== $headers['response_code'] ) {
			// Something unexpected going on, just ignore it.
			return;
		}

		// Ok, we have received a valid response.
		$response = json_decode( $response );
		if ( ! empty( $response->tag_name ) && ( ! isset( $response->prerelease ) || false === $response->prerelease ) ) {
			// Should there be a check for `v` at the start of a version number ?
			$this->current_version = $response->tag_name;
		}
	}

	/**
	 * Retrieve a GitHub oAuth token if one was provided by the user.
	 *
	 * @return string|false Token or false if none was provided.
	 */
	private function get_oauth_token() {
		if ( '' !== $this->github_oauth_token && is_string( $this->github_oauth_token ) ) {
			return $this->github_oauth_token;
		} elseif ( false !== getenv( 'GITHUB_OAUTH_TOKEN' ) ) {
			return getenv( 'GITHUB_OAUTH_TOKEN' );
		} else {
			return false;
		}
	}

	/**
	 * Parse HTTP response headers array to a more usable format.
	 *
	 * Based on http://php.net/manual/en/reserved.variables.httpresponseheader.php#117203
	 *
	 * @param array $headers HTTP response headers array.
	 *
	 * @return array
	 */
	private function parse_response_headers( $headers ) {
		$head = array();
		foreach ( $headers as $key => $value ) {
			$tag = explode( ':', $value, 2 );
			if ( isset( $tag[1] ) ) {
				$head[ trim( $tag[0] ) ] = trim( $tag[1] );
			} else {
				$head[] = $value;
				if ( preg_match( '`HTTP/[0-9\.]+\s+([0-9]+)`', $value, $out ) ) {
					$head['response_code'] = intval( $out[1] );
				}
			}
		}
		return $head;
	}

} // End class.
