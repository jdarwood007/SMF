<?php

/**
 * Simple Machines Forum (SMF)
 *
 * @package SMF
 * @author Simple Machines https://www.simplemachines.org
 * @copyright 2024 Simple Machines and individual contributors
 * @license https://www.simplemachines.org/about/smf/license.php BSD
 *
 * @version 3.0 Alpha 1
 */

declare(strict_types=1);

namespace SMF\Maintenance\Tools;

use Exception;
use SMF\Db\DatabaseApi as Db;
use SMF\Sapi;
use SMF\Lang;
use SMF\Config;
use SMF\Maintenance;
use SMF\Maintenance\Step;
use SMF\Maintenance\Template;
use SMF\Maintenance\ToolsBase;
use SMF\Maintenance\ToolsInterface;
use SMF\PackageManager\FtpConnection;
use SMF\Maintenance\DatabaseInterface;
use SMF\Url;

class Install extends ToolsBase implements ToolsInterface
{
    public bool $continue = true;
    public bool $skip = false;

    private string $script_name = 'Setup.php';

    public function __construct(){
        Maintenance::$languages = $this->detectLanguages(['General', 'Install']);

        if (empty(Maintenance::$languages)) {
            if (!Sapi::isCLI()) {
                Template::missingLanguages();
            }

            throw new Exception('This installer was unable to find this tools\'s language file or files.');
        } else {
            $requested_lang = Maintenance::getRequestedLanguage();

            // Ensure SMF\Lang knows the path to the language directory.
            Lang::addDirs(Config::$languagesdir);

        	// And now load the language file.
            Lang::load('Install', $requested_lang);

            // Assume that the admin likes that language.
            if ($requested_lang !== 'en_US') {
                Config::$language = $requested_lang;
            }
        }
    }

    public function getPageTitle(): string
    {
        return $this->getSteps()[Maintenance::getCurrentStep()]->getTitle() ?? Lang::$txt['smf_installer'];
    }

    public function hasSteps(): bool
    {
        return true;
    }

    /**
     * 
     * @return \SMF\Maintenance\Step[]
     */
    public function getSteps(): array
    {
        return [
            0 => new Step(
                id: 1,
                name: Lang::$txt['install_step_welcome'],
                function: 'Welcome',
                progres: 0
            ),
            1 => new Step(
                id: 2,
                name: Lang::$txt['install_step_writable'],
                function: 'CheckFilesWritable',
                progres: 10
            ),
            2 => new Step(
                id: 3,
                name: Lang::$txt['install_step_databaseset'],
                title: Lang::$txt['db_settings'],
                function: 'DatabaseSettings',
                progres: 15
            ),
            3 => new Step(
                id: 4,
                name: Lang::$txt['install_step_forum'],
                title: Lang::$txt['install_settings'],
                function: 'ForumSettings',
                progres: 40
            ),
            4 => new Step(
                id: 5,
                name: Lang::$txt['install_step_databasechange'],
                title: Lang::$txt['db_populate'],
                function: 'DatabasePopulation',
                progres: 15
            ),
            5 => new Step(
                id: 6,
                name: Lang::$txt['install_step_admin'],
                title: Lang::$txt['user_settings'],
                function: 'AdminAccount',
                progres: 20
            ),
            6 => new Step(
                id: 7,
                name: Lang::$txt['install_step_delete'],
                function: 'DeleteInstall',
                progres: 0
            ),
        ];
    }

    public function getStepTitle(): string
    {
        return $this->getSteps()[Maintenance::getCurrentStep()]->getName();
    }

    public function Welcome(): bool
    {
        // Done the submission?
        if (isset($_POST['contbutt'])) {
            return true;
        }

        if (Maintenance::isInstalled()) {
            Maintenance::$context['warning'] = Lang::$txt['error_already_installed'];
        }

        Maintenance::$context['supported_databases'] = $this->supportedDatabases();

        // Needs to at least meet our miniumn version.
        if ((version_compare(Maintenance::getRequiredVersionForPHP(), PHP_VERSION, '>='))) {
            Maintenance::$fatal_error = Lang::$txt['error_php_too_low'];
            return false;
        }
        // Make sure we have a supported database
        elseif (empty(Maintenance::$context['supported_databases'])) {
            Maintenance::$fatal_error = Lang::$txt['error_db_missing'];
            return false;
        }

        // How about session support?  Some crazy sysadmin remove it?
        if (!function_exists('session_start')) {
            Maintenance::$errors[] = Lang::$txt['error_session_missing'];
        }

        // Make sure they uploaded all the files.
        if (!file_exists(Config::$boarddir . '/index.php')) {
            Maintenance::$errors[] = Lang::$txt['error_missing_files'];
        }
        // Very simple check on the session.save_path for Windows.
        // @todo Move this down later if they don't use database-driven sessions?
        elseif (@ini_get('session.save_path') == '/tmp' && Sapi::isOS(Sapi::OS_WINDOWS)) {
            Maintenance::$errors[] = Lang::$txt['error_session_save_path'];
        }

        // Mod_security blocks everything that smells funny. Let SMF handle security.
        if (!$this->checkAndTryToFixModSecurity() && !isset($_GET['overmodsecurity'])) {
            Maintenance::$context['error'] = Lang::$txt['error_mod_security'] . '<br><br><a href="' . Maintenance::getSelf() . '?overmodsecurity=true">' . Lang::$txt['error_message_click'] . '</a> ' . Lang::$txt['error_message_bad_try_again'];
        }

        // Confirm mbstring is loaded...
        if (!extension_loaded('mbstring')) {
            Maintenance::$errors[] = Lang::$txt['install_no_mbstring'];
        }

        // Confirm fileinfo is loaded...
        if (!extension_loaded('fileinfo')) {
            Maintenance::$errors[] = Lang::$txt['install_no_fileinfo'];
        }

        // Check for https stream support.
        $supported_streams = stream_get_wrappers();

        if (!in_array('https', $supported_streams)) {
            Maintenance::$warnings[] = Lang::$txt['install_no_https'];
        }

        if (empty(Maintenance::$errors)) {
            Maintenance::$context['continue'] = true;
        }

        return false;
    }

    public function CheckFilesWritable()
    {    
        $writable_files = [
            'attachments',
            'avatars',
            'custom_avatar',
            'cache',
            'Packages',
            'Smileys',
            'Themes',
            'Languages/en_US/agreement.txt',
            'Settings.php',
            'Settings_bak.php',
            'cache/db_last_error.php',
        ];
    
        foreach ($this->detectLanguages() as $lang => $temp) {
            $extra_files[] = 'Languages/' . $lang;
        }
    
        // With mod_security installed, we could attempt to fix it with .htaccess.
        if (function_exists('apache_get_modules') && in_array('mod_security', apache_get_modules())) {
            $writable_files[] = file_exists(Config::$boarddir . '/.htaccess') ? '.htaccess' : '.';
        }
    
        $failed_files = [];
    
        // Windows is trickier.  Let's try opening for r+...
        if (Sapi::isOS(Sapi::OS_WINDOWS)) {    
            foreach ($writable_files as $file) {
                // Folders can't be opened for write... but the index.php in them can ;)
                if (is_dir(Config::$boarddir . '/' . $file)) {
                    $file .= '/index.php';
                }
    
                // Funny enough, chmod actually does do something on windows - it removes the read only attribute.
                @chmod(Config::$boarddir . '/' . $file, 0777);
                $fp = @fopen(Config::$boarddir . '/' . $file, 'r+');
    
                // Hmm, okay, try just for write in that case...
                if (!is_resource($fp)) {
                    $fp = @fopen(Config::$boarddir . '/' . $file, 'w');
                }
    
                if (!is_resource($fp)) {
                    $failed_files[] = $file;
                }
    
                @fclose($fp);
            }
    
            foreach ($extra_files as $file) {
                @chmod(Config::$boarddir . (empty($file) ? '' : '/' . $file), 0777);
            }
        } else {
            // On linux, it's easy - just use is_writable!       
            foreach ($writable_files as $file) {
                // Some files won't exist, try to address up front
                if (!file_exists(Config::$boarddir . '/' . $file)) {
                    @touch(Config::$boarddir . '/' . $file);
                }
    
                // NOW do the writable check...
                if (!is_writable(Config::$boarddir . '/' . $file)) {
                    @chmod(Config::$boarddir . '/' . $file, 0755);
    
                    // Well, 755 hopefully worked... if not, try 777.
                    if (!is_writable(Config::$boarddir . '/' . $file) && !@chmod(Config::$boarddir . '/' . $file, 0777)) {
                        $failed_files[] = $file;
                    }
                }
            }
    
            foreach ($extra_files as $file) {
                @chmod(Config::$boarddir . (empty($file) ? '' : '/' . $file), 0777);
            }
        }
    
        $failure = count($failed_files) >= 1;
    
        if (!isset($_SERVER)) {
            return !$failure;
        }
    
        // Put the list into context.
        Maintenance::$context['failed_files'] = $failed_files;
    
        // It's not going to be possible to use FTP on windows to solve the problem...
        if ($failure && Sapi::isOS(Sapi::OS_WINDOWS)) {
            Maintenance::$fatal_error = Lang::$txt['error_windows_chmod'] . '
                        <ul class="error_content">
                            <li>' . implode('</li>
                            <li>', $failed_files) . '</li>
                        </ul>';
    
            return false;
        }
    
        // We're going to have to use... FTP!
        if ($failure) {
            // Load any session data we might have...
            if (!isset($_POST['ftp']['username']) && isset($_SESSION['ftp'])) {
                $_POST['ftp']['server'] = $_SESSION['ftp']['server'];
                $_POST['ftp']['port'] = $_SESSION['ftp']['port'];
                $_POST['ftp']['username'] = $_SESSION['ftp']['username'];
                $_POST['ftp']['password'] = $_SESSION['ftp']['password'];
                $_POST['ftp']['path'] = $_SESSION['ftp']['path'];
            }
    
            Maintenance::$context['ftp_errors'] = [];
    
            if (isset($_POST['ftp_username'])) {
                $ftp = new FtpConnection($_POST['ftp']['server'], $_POST['ftp']['port'], $_POST['ftp']['username'], $_POST['ftp']['password']);
    
                if ($ftp->error === false) {
                    // Try it without /home/abc just in case they messed up.
                    if (!$ftp->chdir($_POST['ftp']['path'])) {
                        Maintenance::$context['ftp_errors'][] = $ftp->last_message;
                        $ftp->chdir(preg_replace('~^/home[2]?/[^/]+?~', '', $_POST['ftp']['path']));
                    }
                }
            }
    
            if (!isset($ftp) || $ftp->error !== false) {
                if (!isset($ftp)) {
                    $ftp = new FtpConnection(null);
                }
                // Save the error so we can mess with listing...
                elseif ($ftp->error !== false && empty(Maintenance::$context['ftp_errors']) && !empty($ftp->last_message)) {
                    Maintenance::$context['ftp_errors'][] = $ftp->last_message;
                }
    
                list($username, $detect_path, $found_path) = $ftp->detect_path(Config::$boarddir);
    
                if (empty($_POST['ftp']['path']) && $found_path) {
                    $_POST['ftp']['path'] = $detect_path;
                }
    
                if (!isset($_POST['ftp']['username'])) {
                    $_POST['ftp']['username'] = $username;
                }
    
                // Set the username etc, into context.
                Maintenance::$context['ftp'] = [
                    'server' => $_POST['ftp']['server'] ?? 'localhost',
                    'port' => $_POST['ftp']['port'] ?? '21',
                    'username' => $_POST['ftp']['username'] ?? '',
                    'path' => $_POST['ftp']['path'] ?? '/',
                    'path_msg' => !empty($found_path) ? Lang::$txt['ftp_path_found_info'] : Lang::$txt['ftp_path_info'],
                ];
    
                return false;
            }
    
    
                $_SESSION['ftp'] = [
                    'server' => $_POST['ftp']['server'],
                    'port' => $_POST['ftp']['port'],
                    'username' => $_POST['ftp']['username'],
                    'password' => $_POST['ftp']['password'],
                    'path' => $_POST['ftp']['path'],
                ];
    
                $failed_files_updated = [];
    
                foreach ($failed_files as $file) {
                    if (!is_writable(Config::$boarddir . '/' . $file)) {
                        $ftp->chmod($file, 0755);
                    }
    
                    if (!is_writable(Config::$boarddir . '/' . $file)) {
                        $ftp->chmod($file, 0777);
                    }
    
                    if (!is_writable(Config::$boarddir . '/' . $file)) {
                        $failed_files_updated[] = $file;
                        Maintenance::$context['ftp_errors'][] = rtrim($ftp->last_message) . ' -> ' . $file . "\n";
                    }
                }
    
                $ftp->close();
    
                // Are there any errors left?
                if (count($failed_files_updated) >= 1) {
                    // Guess there are...
                    Maintenance::$context['failed_files'] = $failed_files_updated;
    
                    // Set the username etc, into context.
                    Maintenance::$context['ftp'] = $_SESSION['ftp'] += [
                        'path_msg' => Lang::$txt['ftp_path_info'],
                    ];
    
                    return false;
                }
    
        }
    
        return true;
    }
    
    public function DatabaseSettings()
    {
        Maintenance::$context['continue'] = true;
        Maintenance::$context['databases'] = [];
        $foundOne = false;

        /** @var \SMF\Maintenance\DatabaseInterface $db */
        foreach ($this->supportedDatabases() as $key => $db) {
            // Not supported, skip.
            if (!$db->isSupported()) {
                continue;
            }

            Maintenance::$context['databases'][$key] = $db;

            // If we have not found a one, set some defaults.
            if (!$foundOne) {
                Maintenance::$context['db'] = [
                    'server' => $db->getDefaultHost(),
                    'user' => $db->getDefaultUser(),
                    'name' => $db->getDefaultName(),
                    'pass' => $db->getDefaultPassword(),
                    'port' => $db->getDefaultPort(),
                    'prefix' => 'smf_',
                    'type' => $key
                ];
            }
        }

        if (isset($_POST['db_user'])) {
            Maintenance::$context['db']['user'] = $_POST['db_user'];
            Maintenance::$context['db']['name'] = $_POST['db_name'];
            Maintenance::$context['db']['server'] = $_POST['db_server'];
            Maintenance::$context['db']['prefix'] = $_POST['db_prefix'];
    
            if (!empty($_POST['db_port'])) {
                Maintenance::$context['db']['port'] = (int) $_POST['db_port'];
            }
        }
    
        // Are we submitting?
        if (!isset($_POST['db_type'])) {
            return false;
        }

		// What type are they trying?
		$db_type = preg_replace('~[^A-Za-z0-9]~', '', $_POST['db_type']);
		$db_prefix = $_POST['db_prefix'];

        if (!isset(Maintenance::$context['databases'][$db_type])) {
            Maintenance::$fatal_error = Lang::$txt['upgrade_unknown_error'];
            return false;
        }

		// Validate the prefix.
        /** @var \SMF\Maintenance\DatabaseInterface $db */
        $db = Maintenance::$context['databases'][$db_type];

        // Use a try/catch here, so we can send specific details about the validation error.
        try {
            if (($db->validatePrefix($db_prefix)) !== true) {
                Maintenance::$fatal_error = Lang::$txt['upgrade_unknown_error'];
                return false;
            }
        }
        catch (Exception $exception) {
            Maintenance::$fatal_error = $exception->getMessage();
            return false;
        }

		// Take care of these variables...
		$vars = [
			'db_type' => $db_type,
			'db_name' => $_POST['db_name'],
			'db_user' => $_POST['db_user'],
			'db_passwd' => $_POST['db_passwd'] ?? '',
			'db_server' => $_POST['db_server'],
			'db_prefix' => $db_prefix,
			// The cookiename is special; we want it to be the same if it ever needs to be reinstalled with the same info.
			'cookiename' => $this->createCookieName($_POST['db_name'], $db_prefix),
		];

		// Only set the port if we're not using the default
		if (!empty($_POST['db_port']) && $db->getDefaultPort() !== (int) $_POST['db_port']) {
            $vars['db_port'] = (int) $_POST['db_port'];
		}

		// God I hope it saved!
        try{
            if (!$this->updateSettingsFile($vars)) {
                Maintenance::$fatal_error = Lang::$txt['settings_error'];
                return false;
            }    
        } catch (Exception $exception) {
            Maintenance::$fatal_error = Lang::$txt['settings_error'];
            return false;
        }

		// Update SMF\Config with the changes we just saved.
		Config::load();

		// Better find the database file!
		if (!file_exists(Config::$sourcedir . '/Db/APIs/' . Db::getClass(Config::$db_type) . '.php')) {
			Maintenance::$fatal_error = sprintf(Lang::$txt['error_db_file'], 'Db/APIs/' . Db::getClass(Config::$db_type) . '.php');
			return false;
		}

        // We need to make some queries, that would trip up our normal security checks.
		Config::$modSettings['disableQueryCheck'] = true;

		// Attempt a connection.
		$needsDB = !empty($databases[Config::$db_type]['always_has_db']);

		Db::load(['non_fatal' => true, 'dont_select_db' => !$needsDB]);

		// Still no connection?  Big fat error message :P.
		if (!Db::$db->connection) {
			// Get error info...  Recast just in case we get false or 0...
			$error_message = Db::$db->connect_error();

			if (empty($error_message)) {
				$error_message = '';
			}
			$error_number = Db::$db->connect_errno();

			if (empty($error_number)) {
				$error_number = '';
			}
			$db_error = (!empty($error_number) ? $error_number . ': ' : '') . $error_message;

			Maintenance::$fatal_error = Lang::$txt['error_db_connect'] . '<div class="error_content"><strong>' . $db_error . '</strong></div>';

			return false;
		}

		// Do they meet the install requirements?
		// @todo Old client, new server?
		if (($db_version = $db->getServerVersion()) === false || version_compare($db->getMinimumVersion(), preg_replace('~^\D*|\-.+?$~', '', $db_version = $db->getServerVersion())) > 0) {
			Maintenance::$fatal_error = sprintf(Lang::$txt['error_db_too_low'], $db->getTitle());
			return false;
		}

        // Let's try that database on for size... assuming we haven't already lost the opportunity.
        if (Db::$db->name != '' && !$needsDB) {
            Db::$db->query(
                '',
                'CREATE DATABASE IF NOT EXISTS `' . Db::$db->name . '`',
                [
                    'security_override' => true,
                    'db_error_skip' => true,
                ],
                Db::$db->connection,
            );

            // Okay, let's try the prefix if it didn't work...
            if (!Db::$db->select(Db::$db->name, Db::$db->connection) && Db::$db->name != '') {
                Db::$db->query(
                    '',
                    'CREATE DATABASE IF NOT EXISTS `' . Db::$db->prefix . Db::$db->name . '`',
                    [
                        'security_override' => true,
                        'db_error_skip' => true,
                    ],
                    Db::$db->connection,
                );

                if (Db::$db->select(Db::$db->prefix . Db::$db->name, Db::$db->connection)) {
                    Db::$db->name = Db::$db->prefix . Db::$db->name;
                    $this->updateSettingsFile(['db_name' => Db::$db->name]);
                }
            }

            // Okay, now let's try to connect...
            if (!Db::$db->select(Db::$db->name, Db::$db->connection)) {
                $incontext['error'] = sprintf(Lang::$txt['error_db_database'], Db::$db->name);

                return false;
            }
        }

        // Everything looks good, lets get on with it.
        return true;
    }

    public function ForumSettings()
    {
        // Let's see if we got the database type correct.
        if (isset($_POST['db_type'], $this->supportedDatabases()[$_POST['db_type']])) {
            Config::$db_type = $_POST['db_type'];

            try{
                if (!$this->updateSettingsFile(['db_type' => Config::$db_type])) {
                    Maintenance::$fatal_error = Lang::$txt['settings_error'];
                    return false;
                }    
            } catch (Exception $exception) {
                Maintenance::$fatal_error = Lang::$txt['settings_error'];
                return false;
            }

            Config::load();
        }
        else {
            // Else we'd better be able to get the connection.
            $this->loadDatabase();
        }

        $host = $this->defaultHost();
        $secure = Sapi::httpsOn();

        // Now, to put what we've learned together... and add a path.
        Maintenance::$context['detected_url'] = 'http' . ($secure ? 's' : '') . '://' . $host . substr(Maintenance::getSelf(), 0, strrpos(Maintenance::getSelf(), '/'));

        // Check if the database sessions will even work.
        Maintenance::$context['test_dbsession'] = (ini_get('session.auto_start') != 1);

        Maintenance::$context['continue'] = true;

        $db = $this->getMaintenanceDatabase(Config::$db_type);

        // We have a failure of database configuration.
        try{
            if (!$db->checkConfiguration()) {
                Maintenance::$fatal_error = Lang::$txt['upgrade_unknown_error'];
                return false;
            }    
        } catch (Exception $exception) {
            Maintenance::$fatal_error = $exception->getMessage();
            return false;
        }

        // Setup the SSL checkbox...
        Maintenance::$context['ssl_chkbx_protected'] = false;
        Maintenance::$context['ssl_chkbx_checked'] = false;

        // If redirect in effect, force SSL ON.
        $url = new Url(Maintenance::$context['detected_url']);

        if ($url->redirectsToHttps()) {
            Maintenance::$context['ssl_chkbx_protected'] = true;
            Maintenance::$context['ssl_chkbx_checked'] = true;
            $_POST['force_ssl'] = true;
        }

        // If no cert, make sure SSL stays OFF.
        if (!$url->hasSSL()) {
            Maintenance::$context['ssl_chkbx_protected'] = true;
            Maintenance::$context['ssl_chkbx_checked'] = false;
        }

        // Submitting?
        if (!isset($_POST['boardurl'])) {
            return false;
        }

		// Deal with different operating systems' directory structure...
		$path = rtrim(str_replace(DIRECTORY_SEPARATOR, '/', Maintenance::getBaseDir()), '/');

		// Save these variables.
		$vars = [
			'boardurl' => $this->cleanBoardUrl($_POST['boardurl']),
			'boarddir' => $path,
			'sourcedir' => $path . '/Sources',
			'cachedir' => $path . '/cache',
			'packagesdir' => $path . '/Packages',
			'languagesdir' => $path . '/Languages',
			'mbname' => strtr($_POST['mbname'], ['\"' => '"']),
			'language' => Maintenance::getRequestedLanguage(),
			'image_proxy_secret' => $this->createImageProxySecret(),
			'image_proxy_enabled' => !empty($_POST['force_ssl']),
			'auth_secret' => $this->createAuthSecret(),
		];

        try{
            if (!$this->updateSettingsFile($vars)) {
                Maintenance::$fatal_error = Lang::$txt['settings_error'];
                return false;
            }    
        } catch (Exception $exception) {
            Maintenance::$fatal_error = Lang::$txt['settings_error'];
            return false;
        }

		// Update SMF\Config with the changes we just saved.
		Config::load();

		// UTF-8 requires a setting to override the language charset.
        try{
            if (!$db->utf8Configured()) {
                Maintenance::$fatal_error = Lang::$txt['error_utf8_support'];
                return false;
            }    
        } catch (Exception $exception) {
            Maintenance::$fatal_error = $exception->getMessage();
            return false;
        }

		// Set the character set here.
        try{
            if (!$this->updateSettingsFile(['db_character_set' => 'utf8'], true)) {
                Maintenance::$fatal_error = Lang::$txt['settings_error'];
                return false;
            }    
        } catch (Exception $exception) {
            Maintenance::$fatal_error = Lang::$txt['settings_error'];
            return false;
        }

		// Good, skip on.
		return true;
    }

    public function DatabasePopulation(): bool
    {
        Maintenance::$context['continue'] = true;

        // Already done?
        if (isset($_POST['pop_done'])) {
            return true;
        }

        // Reload settings.
        Config::load();
        $this->loadDatabase();
        $newSettings = [];
		$path = rtrim(str_replace(DIRECTORY_SEPARATOR, '/', Maintenance::getBaseDir()), '/');

        // Before running any of the queries, let's make sure another version isn't already installed.
        $result = Db::$db->query(
            '',
            'SELECT variable, value
            FROM {db_prefix}settings',
            [
                'db_error_skip' => true,
            ],
        );

        if ($result !== false) {
            while ($row = Db::$db->fetch_assoc($result)) {
                Config::$modSettings[$row['variable']] = $row['value'];
            }

            Db::$db->free_result($result);

            // Do they match?  If so, this is just a refresh so charge on!
            if (!isset(Config::$modSettings['smfVersion']) || Config::$modSettings['smfVersion'] != SMF_VERSION) {
                Maintenance::$fatal_error = Lang::$txt['error_versions_do_not_match'];

                return false;
            }
        }
        Config::$modSettings['disableQueryCheck'] = true;

        // Windows likes to leave the trailing slash, which yields to C:\path\to\SMF\/attachments...
        if (Sapi::isOS(Sapi::OS_WINDOWS)) {
            $attachdir = $path . 'attachments';
        } else {
            $attachdir = $path . '/attachments';
        }

        $replaces = [
            '{$db_prefix}' => Db::$db->prefix,
            '{$attachdir}' => json_encode([1 => Db::$db->escape_string($attachdir)]),
            '{$boarddir}' => Db::$db->escape_string(Config::$boarddir),
            '{$boardurl}' => Config::$boardurl,
            '{$enableCompressedOutput}' => isset($_POST['compress']) ? '1' : '0',
            '{$databaseSession_enable}' => isset($_POST['dbsession']) ? '1' : '0',
            '{$smf_version}' => SMF_VERSION,
            '{$current_time}' => time(),
            '{$sched_task_offset}' => 82800 + mt_rand(0, 86399),
            '{$registration_method}' => $_POST['reg_mode'] ?? 0,
        ];
 
        foreach (Lang::$txt as $key => $value) {
            if (substr($key, 0, 8) == 'default_') {
                $replaces['{$' . $key . '}'] = Db::$db->escape_string($value);
            }
        }
        $replaces['{$default_reserved_names}'] = strtr($replaces['{$default_reserved_names}'], ['\\\\n' => '\\n']);
    
        $existing_tables = Db::$db->list_tables(Config::$db_name, Config::$db_prefix);

        $install_tables = $this->getTables(Config::$sourcedir . '/Maintenance/Schema/');

        // $tables->seek(Maintenance::getCurrentSubStep());

        foreach ($install_tables as $tbl) {
            if (in_array(Config::$db_prefix . $tbl->getName(), $existing_tables)) {
                continue;
            }

            // Prepare the table data.
            $table_name = Config::$db_prefix . $tbl->getName();
            $columns = $tbl->getColumnsForCreateTable(); 
            $indexes = $tbl->getIndexesForCreateTable();
            
            var_dump(Db::$db->create_table($table_name, $columns, $indexes));

            //var_dump($columns, $indexes);
        }

        return false;
    }


    // Create an .htaccess file to prevent mod_security. SMF has filtering built-in.
    private function checkAndTryToFixModSecurity(): bool
    {
        $htaccess_addition = '
    <IfModule mod_security.c>
        # Turn off mod_security filtering.  SMF is a big boy, it doesn\'t need its hands held.
        SecFilterEngine Off

        # The below probably isn\'t needed, but better safe than sorry.
        SecFilterScanPOST Off
    </IfModule>';

        if (!function_exists('apache_get_modules') || !in_array('mod_security', apache_get_modules())) {
            return true;
        }

        if (file_exists(Config::$boarddir . '/.htaccess') && is_writable(Config::$boarddir . '/.htaccess')) {
            $current_htaccess = implode('', file(Config::$boarddir . '/.htaccess'));

            // Only change something if mod_security hasn't been addressed yet.
            if (strpos($current_htaccess, '<IfModule mod_security.c>') === false) {
                if ($ht_handle = fopen(Config::$boarddir . '/.htaccess', 'a')) {
                    fwrite($ht_handle, $htaccess_addition);
                    fclose($ht_handle);

                    return true;
                }

                    return false;
            }

                return true;
        }

        if (file_exists(Config::$boarddir . '/.htaccess')) {
            return strpos(implode('', file(Config::$boarddir . '/.htaccess')), '<IfModule mod_security.c>') !== false;
        }

        if (is_writable(Config::$boarddir)) {
            if ($ht_handle = fopen(Config::$boarddir . '/.htaccess', 'w')) {
                fwrite($ht_handle, $htaccess_addition);
                fclose($ht_handle);

                return true;
            }

                return false;
        }

            return false;
    }

    private function createCookieName(string $db_name, string $db_prefix) {
        return 'SMFCookie' . abs(crc32($db_name . preg_replace('~[^A-Za-z0-9_$]~', '', $db_prefix)) % 1000);
    }

    private function createAuthSecret() {
        return bin2hex(random_bytes(32));
    }
    
    private function createImageProxySecret() {
        return bin2hex(random_bytes(10));
    }
    private function updateSettingsFile($vars, $rebuild = false): bool
    {
        if (!is_writable(SMF_SETTINGS_FILE)) {
            @chmod(SMF_SETTINGS_FILE, 0777);

            if (!is_writable(SMF_SETTINGS_FILE)) {
                return false;
            }
        }

        return Config::updateSettingsFile($vars, false, $rebuild);
    }

    private function loadDatabase(): void
    {
        // Connect the database.
        if (empty(Db::$db->connection)) {
            Db::load();
        }
    }

    private function getMaintenanceDatabase(string $db_type): DatabaseInterface
    {
        /** @var \SMF\Maintenance\DatabaseInterface $db_class */
        $db_class = '\\SMF\\Maintenance\\Database\\' . $db_type;
        require_once Config::$sourcedir . '/Maintenance/Database/' . $db_type . '.php';
        return new $db_class();        
    }

    private function defaultHost(): string
    {
        return empty($_SERVER['HTTP_HOST']) ? $_SERVER['SERVER_NAME'] . (empty($_SERVER['SERVER_PORT']) || $_SERVER['SERVER_PORT'] == '80' ? '' : ':' . $_SERVER['SERVER_PORT']) : $_SERVER['HTTP_HOST'];
    }

    private function cleanBoardUrl(string $boardurl): string
    {
		if (substr($boardurl, -10) == '/index.php') {
			$boardurl = substr($boardurl, 0, -10);
		} elseif (substr($boardurl, -1) == '/') {
			$boardurl = substr($boardurl, 0, -1);
		}

		if (substr($boardurl, 0, 7) != 'http://' && substr($boardurl, 0, 7) != 'file://' && substr($boardurl, 0, 8) != 'https://') {
			$boardurl = 'http://' . $boardurl;
		}

		// Make sure boardurl is aligned with ssl setting
		if (empty($_POST['force_ssl'])) {
			$boardurl = strtr($boardurl, ['https://' => 'http://']);
		} else {
			$boardurl = strtr($boardurl, ['http://' => 'https://']);
		}

		// Make sure international domain names are normalized correctly.
		if (Lang::$txt['lang_character_set'] == 'UTF-8') {
			$boardurl = (string) new Url($boardurl, true);
		}

        return $boardurl;
    }

     /**
     * 
     * @return \SMF\Maintenance\SchemaInterface&\SMF\Maintenance\SchemaBase[]
     */   
    private function getTables($directory): \ArrayIterator
    {
        $files = [];

        foreach (new \DirectoryIterator($directory) as $fileInfo) {
            if ($fileInfo->isDot() || $fileInfo->isDir() || $fileInfo->getExtension() !== 'php') {
                continue;
            }
            $tbl = $fileInfo->getBasename('.' . $fileInfo->getExtension());

            /** @var \SMF\Maintenance\SchemaInterface&\SMF\Maintenance\SchemaBase $tbl_class */
            $tbl_class = '\\SMF\\Maintenance\\Schema\\' . $tbl;
            require_once Config::$sourcedir . '/Maintenance/Schema/' . $fileInfo->getFilename();
            $files[$tbl] = new $tbl_class();
        }

        return new \ArrayIterator($files);
    }
}
