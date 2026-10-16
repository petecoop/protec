<?php

declare(strict_types=1);

namespace Petecoop\Protec;

class Patterns
{
    public const WORDPRESS = [
        'wp-admin',
        'wp-admin/*',
        'wp-login',
        'wp-login.php',
        'wp-config*',
        'wp-includes/*',
        'wp-content/*',
        'wp-json',
        'wp-json/*',
        'wordpress',
        'wordpress/*',
        'xmlrpc.php',
    ];

    public const CONFIGURATION = [
        '.env',
        '.env.*',
        '*/.env',
        '*/.env.*',
        '.aws/*',
        '.docker/*',
        '.vscode/sftp.json',
        'docker-compose.yml',
        'docker-compose.yaml',
        'terraform.tfstate',
    ];

    public const VERSION_CONTROL = [
        '.git',
        '.git/*',
        '*/.git/*',
        '.svn',
        '.svn/*',
        '.hg',
        '.hg/*',
    ];

    public const DATABASE = [
        'phpmyadmin',
        'phpmyadmin/*',
        'phpmyadmin*',
        'pma',
        'pma/*',
        'adminer.php',
        'adminer-*.php',
        '*.sql',
        '*.sql.gz',
    ];

    public const PHP = ['phpinfo.php', 'info.php', 'vendor/phpunit/*'];

    public const LARAVEL = ['_ignition/execute-solution', 'storage/logs/*', 'artisan'];

    public const TELESCOPE = ['telescope', 'telescope/*'];

    public const SERVERS = ['server-status', 'server-info', 'cgi-bin/*', 'access.log'];

    public const OTHER_PLATFORMS = [
        'actuator',
        'actuator/*',
        'owa/auth/logon.jsp',
        'solr/*',
        'geoserver/*',
        'jenkins/*',
        'sitecore/*',
        'umbraco/*',
    ];
}
