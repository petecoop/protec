<?php

declare(strict_types=1);

use Petecoop\Protec\DetectorRegistry;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Patterns;

beforeEach(function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy.attempts', 1);
});

it('can disable a group while retaining the remaining groups', function () {
    $patterns = config('protec.detectors.'.ScannerProbe::class.'.patterns');
    config()->set(
        'protec.detectors.'.ScannerProbe::class.'.patterns',
        array_values(array_filter(
            $patterns,
            static fn (string|array $pattern): bool => $pattern !== Patterns::TELESCOPE,
        )),
    );

    $this->get('/telescope')->assertNotFound();
    $this->get('/telescope/requests')->assertNotFound();
    $this->assertDatabaseCount('ip_blocks', 0);
    $this->get('/wp-login.php')->assertTooManyRequests();
});

it('allows the scanner pattern list to be replaced in config', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.patterns', ['private-admin/*']);

    $this->get('/.env')->assertNotFound();
    $this->get('/private-admin/users')->assertTooManyRequests();
});

it('can exclude paths without bypassing other matches or existing blocks', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.except', ['TELESCOPE', 'telescope/*']);

    $this->get('/telescope')->assertNotFound();
    $this->get('/telescope/requests')->assertNotFound();
    $this->get('/.env')->assertTooManyRequests();
    $this->get('/telescope')->assertTooManyRequests();
});

it('recognizes paths from the expanded scanner catalogue', function (string $path) {
    $this->get($path)->assertTooManyRequests();
})->with([
    '/wp-json/wp/v2/users',
    '/wp-content/plugins/test',
    '/.svn/entries',
    '/nested/.git/HEAD',
    '/nested/.env.production',
    '/.aws/credentials',
    '/adminer.php',
    '/phpinfo.php',
    '/_ignition/execute-solution',
    '/actuator/health',
    '/server-status',
]);

it('avoids broad substring matches for ordinary application paths', function (string $path) {
    $this->get($path)->assertNotFound();
    $this->assertDatabaseCount('ip_blocks', 0);
})->with(['/roadmap', '/my-config.json', '/archive.zip', '/telescope-guide']);

it('recognizes storage log probes when they reach the detector as a 404', function () {
    // Laravel versions differ in whether their local file-serving route
    // intercepts this path with a 403 before it can become a 404.
    $inspection = new Petecoop\Protec\Data\Inspection(
        Illuminate\Http\Request::create('/storage/logs/laravel.log'),
        response('', status: 404),
    );

    expect(app(DetectorRegistry::class)->detector(ScannerProbe::class)->detect($inspection)->context)->toBe([
        'pattern' => 'storage/logs/*',
    ]);
});

it('mixes built-in pattern sets with custom paths', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.patterns', [Patterns::WORDPRESS, 'custom-probe/*']);
    $this->get('/.env')->assertNotFound();
    $this->get('/custom-probe/test')->assertTooManyRequests();
    Petecoop\Protec\Facades\Protec::unblock('127.0.0.1');
    $this->get('/wp-login.php')->assertTooManyRequests();
});

it('can disable scanner matching by supplying an empty pattern list', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.patterns', []);
    $this->get('/.env')->assertNotFound();
    $this->assertDatabaseCount('ip_blocks', 0);
});

it('keeps scanner patterns out of other detector configurations', function () {
    expect(config('protec.detectors.'.Petecoop\Protec\Detectors\CorruptLivewirePayload::class))
        ->not->toHaveKey('patterns')
        ->not->toHaveKey('except');
});

it('can export and restore config containing pattern arrays', function () {
    $configuration = require __DIR__.'/../../config/protec.php';
    $file = tempnam(sys_get_temp_dir(), prefix: 'protec-config-');
    try {
        file_put_contents($file, '<?php return '.var_export($configuration, return: true).';');
        $restored = require $file;
        expect($restored['detectors'][ScannerProbe::class]['patterns'])
            ->toBe($configuration['detectors'][ScannerProbe::class]['patterns']);
    } finally {
        unlink($file);
    }
});

it('accepts custom arrays alongside built-in pattern constants', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.patterns', [
        Patterns::WORDPRESS,
        ['custom-probe/*', 'debug.php'],
    ]);

    $this->get('/custom-probe/test')->assertTooManyRequests();
    Petecoop\Protec\Facades\Protec::unblock('127.0.0.1');
    $this->get('/wp-login.php')->assertTooManyRequests();
});

it('allows a built-in set to be trimmed and extended with normal array operations', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.patterns', [
        ...array_diff(Patterns::WORDPRESS, ['wp-login.php']),
        'custom-probe/*',
    ]);

    $this->get('/wp-login.php')->assertNotFound();
    $this->get('/wp-admin/setup-config.php')->assertTooManyRequests();
    Petecoop\Protec\Facades\Protec::unblock('127.0.0.1');
    $this->get('/custom-probe/test')->assertTooManyRequests();
});
