<?php

declare(strict_types=1);

namespace Petecoop\Protec\Detectors;

use Illuminate\Support\Str;
use Petecoop\Protec\Contracts\Detector;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Inspection;

class ScannerProbe implements Detector
{
    public function detect(Inspection $inspection): ?Detection
    {
        if ($inspection->response?->getStatusCode() !== 404 || $inspection->exception !== null) {
            return null;
        }

        $path = Str::lower(ltrim(rawurldecode($inspection->request->getPathInfo()), characters: '/'));

        foreach ($this->patterns() as $pattern) {
            if (Str::is(Str::lower($pattern), $path)) {
                return new Detection('scanner-probe', ['pattern' => $pattern]);
            }
        }

        return null;
    }

    /** @return list<string> */
    public function patterns(): array
    {
        return [
            'wp-admin',
            'wp-admin/*',
            'wp-login.php',
            'wp-config*',
            'wp-includes/*',
            'xmlrpc.php',
            '.env',
            '.env.*',
            '.git',
            '.git/*',
            '.aws/credentials',
            'phpmyadmin',
            'phpmyadmin/*',
            'vendor/phpunit/*',
            'docker-compose.yml',
            'docker-compose.yaml',
            'terraform.tfstate',
            'access.log',
            '*.sql',
            '*.sql.gz',
            'telescope',
            'telescope/*',
        ];
    }
}
