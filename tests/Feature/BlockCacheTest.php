<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Tests\Fixtures\CustomBlock;

it('makes no database queries for previously unseen guest IPs with a non-database cache', function () {
    DB::enableQueryLog();

    $this->get('/ok')->assertOk();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.1'])->get('/ok')->assertOk();

    expect(DB::getQueryLog())->toBeEmpty();
});

it('does not fall back to stored blocks when an IP is absent from the cache', function () {
    IpBlock::create(['ip_address' => '127.0.0.1', 'expires_at' => null]);
    DB::enableQueryLog();

    $this->get('/ok')->assertOk();

    expect(DB::getQueryLog())->toBeEmpty();
});

it('publishes manual blocks and removes them on unblocking without lookup queries', function () {
    Protec::block('127.0.0.1', reason: 'review');
    DB::enableQueryLog();
    $this->get('/ok')->assertTooManyRequests();
    expect(DB::getQueryLog())->toBeEmpty();

    Protec::unblock('127.0.0.1');
    DB::flushQueryLog();
    $this->get('/ok')->assertOk();
    expect(DB::getQueryLog())->toBeEmpty();
});

it('publishes automatic detector blocks to the cache', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy.attempts', 1);
    $this->get('/.env')->assertTooManyRequests();
    DB::enableQueryLog();

    $this->get('/ok')->assertTooManyRequests();

    expect(DB::getQueryLog())->toBeEmpty();
});

it('queries directly for a database cache driver even with a custom store name', function (
    string $store,
    string $defaultStore,
) {
    config()->set([
        'protec.cache_store' => $store,
        'cache.default' => $defaultStore,
        'cache.limiter' => 'array',
        'cache.stores.sql-cache' => [
            'driver' => 'database',
            'connection' => 'testing',
            // This table deliberately does not exist: block checks must bypass it.
            'table' => 'unused_cache',
        ],
    ]);

    Protec::block('127.0.0.1');
    Cache::store('array')->flush();
    DB::enableQueryLog();
    $this->get('/ok')->assertTooManyRequests();
    expect(DB::getQueryLog())->not->toBeEmpty();
    foreach (DB::getQueryLog() as $query) {
        expect($query['query'])->not->toContain('unused_cache');
    }

    Protec::unblock('127.0.0.1');
    $this->get('/ok')->assertOk();
})->with(['application default' => ['default', 'sql-cache'], 'Protec override' => ['sql-cache', 'array']]);

it('uses a named block store for checks, updates, unblocking, and refilling', function (string $defaultStore) {
    config()->set([
        'protec.cache_store' => 'protec-blocks',
        'cache.default' => $defaultStore,
        'cache.limiter' => 'array',
        'cache.stores.protec-blocks' => ['driver' => 'array'],
        'cache.stores.sql-cache' => ['driver' => 'database', 'connection' => 'testing', 'table' => 'unused_cache'],
    ]);

    Protec::block('127.0.0.1');
    Cache::store('array')->flush();
    DB::enableQueryLog();
    $this->get('/ok')->assertTooManyRequests();
    expect(DB::getQueryLog())->toBeEmpty();

    Cache::store('protec-blocks')->flush();
    $this->get('/ok')->assertOk();
    expect(DB::getQueryLog())->toBeEmpty();

    $this->artisan('protec:cache')->expectsOutput('Block cache refreshed for 1 IP addresses.')->assertSuccessful();
    DB::flushQueryLog();
    $this->get('/ok')->assertTooManyRequests();
    expect(DB::getQueryLog())->toBeEmpty();

    Protec::unblock('127.0.0.1');
    DB::flushQueryLog();
    $this->get('/ok')->assertOk();
    expect(DB::getQueryLog())->toBeEmpty();
})->with(['array default' => 'array', 'database default' => 'sql-cache']);

it('keeps a permanent cache entry when a shorter manual block is added', function () {
    $this->freezeSecond();
    $permanent = Protec::block('127.0.0.1');
    Protec::block('127.0.0.1', for: 1);
    $this->travel(365)->days();
    DB::enableQueryLog();

    $cached = Protec::blocked(Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']));
    expect($cached->is($permanent))->toBeTrue();
    $this->get('/ok')->assertTooManyRequests();
    expect(DB::getQueryLog())->toBeEmpty();
});

it('caches the longest overlapping temporary block until its exact expiration', function () {
    $this->freezeSecond();
    Protec::block('127.0.0.1', for: '2d');
    Protec::block('127.0.0.1', for: '1d');
    $this->travel(1)->days();
    DB::enableQueryLog();

    $this->get('/ok')->assertTooManyRequests();
    $this->travel(1)->days();
    $this->get('/ok')->assertOk();

    expect(DB::getQueryLog())->toBeEmpty();
});

it('restores configured models and casts from cached attributes for normalized IPv6 addresses', function () {
    Schema::rename('protec_ip_blocks', 'custom_ip_blocks');
    config()->set('protec.model', CustomBlock::class);
    Protec::block('2001:db8::1', reason: 'review', context: ['ticket' => 1]);
    DB::enableQueryLog();

    $block = Protec::blocked(Request::create('/', server: [
        'REMOTE_ADDR' => '2001:0db8:0000:0000:0000:0000:0000:0001',
    ]));

    expect($block)
        ->toBeInstanceOf(CustomBlock::class)
        ->and($block->ip_address)
        ->toBe('2001:db8::1')
        ->and($block->reason)
        ->toBe('review')
        ->and($block->context)
        ->toBe(['ticket' => 1])
        ->and(DB::getQueryLog())
        ->toBeEmpty();
});

it('uses file caching without requiring cached PHP classes to be unserializable', function () {
    $directory = sys_get_temp_dir().'/protec-cache-'.Str::uuid();
    config()->set([
        'cache.default' => 'protec-file',
        'cache.limiter' => 'array',
        'cache.serializable_classes' => false,
        'cache.stores.protec-file' => ['driver' => 'file', 'path' => $directory],
    ]);

    try {
        Protec::block('127.0.0.1', context: ['ticket' => 1]);
        Cache::purge('protec-file');
        DB::enableQueryLog();

        $this->get('/ok')->assertTooManyRequests();
        expect(DB::getQueryLog())->toBeEmpty();
    } finally {
        Cache::purge('protec-file');
        File::deleteDirectory($directory);
    }
});

it('updates the cache only after an outer block transaction commits', function () {
    DB::transaction(fn () => Protec::block('127.0.0.1'));
    DB::enableQueryLog();

    $this->get('/ok')->assertTooManyRequests();

    expect(DB::getQueryLog())->toBeEmpty();
});

it('does not cache a block when an outer transaction rolls back', function () {
    expect(fn () => DB::transaction(function () {
        Protec::block('127.0.0.1');

        throw new RuntimeException('Rollback');
    }))
        ->toThrow(RuntimeException::class, 'Rollback');
    $this->assertDatabaseCount('protec_ip_blocks', 0);
    DB::enableQueryLog();

    $this->get('/ok')->assertOk();

    expect(DB::getQueryLog())->toBeEmpty();
});

it('does not remove a cached block when an unblock transaction rolls back', function () {
    Protec::block('127.0.0.1');
    expect(fn () => DB::transaction(function () {
        Protec::unblock('127.0.0.1');

        throw new RuntimeException('Rollback');
    }))
        ->toThrow(RuntimeException::class, 'Rollback');
    DB::enableQueryLog();

    $this->get('/ok')->assertTooManyRequests();

    expect(DB::getQueryLog())->toBeEmpty();
});

it('removes cached blocks after an outer unblock transaction commits', function () {
    Protec::block('127.0.0.1');
    DB::transaction(fn () => Protec::unblock('127.0.0.1'));
    DB::enableQueryLog();

    $this->get('/ok')->assertOk();

    expect(DB::getQueryLog())->toBeEmpty();
});
