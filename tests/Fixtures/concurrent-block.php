<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Sleep;
use Orchestra\Testbench\Foundation\Application as Testbench;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Protec;

require __DIR__.'/../../vendor/autoload.php';

[$script, $directory, $worker] = $argv;

$app = Testbench::create(options: ['enabled_package_discoveries' => false]);
$app['config']->set([
    'database.default' => 'testing',
    'database.connections.testing' => [
        'driver' => 'sqlite',
        'database' => $directory.'/blocks.sqlite',
        'busy_timeout' => 5000,
    ],
    'cache.default' => 'array',
    'cache.limiter' => 'file',
    'cache.stores.file' => ['driver' => 'file', 'path' => $directory.'/cache'],
    'protec.enabled' => true,
    'protec.exemptions' => [],
    'protec.detectors' => [],
]);

$protec = new class extends Protec {
    protected function blockAttributes(?string $detector, Detection $detection, ?int $seconds): array
    {
        // Widen the insertion race so both workers reach block creation together.
        Sleep::usleep(100_000);

        return parent::blockAttributes($detector, $detection, $seconds);
    }
};

touch($directory.'/ready-'.$worker);
$deadline = microtime(true) + 5;
while (! is_file($directory.'/start')) {
    if (microtime(true) > $deadline) {
        throw new RuntimeException('Timed out waiting for the concurrency test to start.');
    }

    Sleep::usleep(1000);
}

$block = $protec->record(
    Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.1']),
    new Detection,
    new Limit(attempts: 1),
);

echo $block->getKey();
