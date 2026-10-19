<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Petecoop\Protec\Models\IpBlock;
use Symfony\Component\Process\Process;

it('creates one automatic block when concurrent requests cross the threshold', function () {
    $directory = sys_get_temp_dir().'/protec-concurrency-'.Str::uuid();
    File::ensureDirectoryExists($directory);
    touch($directory.'/blocks.sqlite');
    $workers = [];

    try {
        config()->set('database.connections.testing.database', $directory.'/blocks.sqlite');
        DB::purge('testing');
        (require __DIR__.'/../../database/migrations/create_ip_blocks_table.php')->up();

        foreach ([1, 2] as $worker) {
            $process = new Process([
                PHP_BINARY,
                __DIR__.'/../Fixtures/concurrent-block.php',
                $directory,
                (string) $worker,
            ]);
            $process->setTimeout(10)->start();
            $workers[] = $process;
        }

        $deadline = microtime(true) + 5;
        while (! is_file($directory.'/ready-1') || ! is_file($directory.'/ready-2')) {
            if (microtime(true) > $deadline) {
                throw new RuntimeException(
                    'Workers did not become ready: '
                        .implode('', array_map(
                            fn (Process $process): string => $process->getOutput().$process->getErrorOutput(),
                            $workers,
                        )),
                );
            }

            Sleep::usleep(1000);
        }
        touch($directory.'/start');

        foreach ($workers as $process) {
            $process->wait();
            expect($process->isSuccessful())->toBeTrue($process->getOutput().$process->getErrorOutput());
        }

        expect($workers[0]->getOutput())->toBe($workers[1]->getOutput());
        $this->assertDatabaseCount('ip_blocks', 1);
        expect(IpBlock::query()->sole()->isActive())->toBeTrue();
    } finally {
        foreach ($workers as $process) {
            $process->stop();
        }

        DB::purge('testing');
        File::deleteDirectory($directory);
    }
});
