<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Tests\Fixtures\CustomBlock;

it('refills unique active IPs while excluding expired and unblocked records', function () {
    $this->freezeSecond();
    IpBlock::create(['ip_address' => '127.0.0.1']);
    IpBlock::create(['ip_address' => '203.0.113.1', 'expires_at' => now()->addMinutes(2)]);
    IpBlock::create(['ip_address' => '203.0.113.1', 'expires_at' => now()->addMinute()]);
    IpBlock::create(['ip_address' => '203.0.113.2', 'expires_at' => now()]);
    IpBlock::create(['ip_address' => '203.0.113.3', 'unblocked_at' => now()]);
    Cache::flush();
    Cache::put('unrelated', 'keep', 600);

    $this
        ->artisan('protec:cache')
        ->expectsOutput('Block cache refreshed for 2 IP addresses.')
        ->assertSuccessful();

    $this->assertDatabaseCount('protec_ip_blocks', 5);
    expect(Cache::get('unrelated'))->toBe('keep');
    DB::enableQueryLog();
    $this->get('/ok')->assertTooManyRequests();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.1'])->get('/ok')->assertTooManyRequests();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.2'])->get('/ok')->assertOk();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.3'])->get('/ok')->assertOk();
    expect(DB::getQueryLog())->toBeEmpty();
});

it('restores original expiry and the longest overlapping block after a cache clear', function () {
    $this->freezeSecond();
    $longest = Protec::block('127.0.0.1', for: 60);
    Protec::block('127.0.0.1', for: 40);
    $this->travel(30)->seconds();
    Cache::flush();

    expect(Protec::warmCache())->toBe(1);
    DB::enableQueryLog();
    $block = Protec::blocked(Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']));
    expect($block->is($longest))->toBeTrue();
    $this->travel(29)->seconds();
    $this->get('/ok')->assertTooManyRequests();
    $this->travel(1)->seconds();
    $this->get('/ok')->assertOk();
    expect(DB::getQueryLog())->toBeEmpty();
});

it('restores permanent blocks without giving them an expiry', function () {
    $this->freezeSecond();
    Protec::block('127.0.0.1');
    Protec::block('127.0.0.1', for: '1d');
    Cache::flush();

    expect(Protec::warmCache())->toBe(1);
    $this->travel(365)->days();
    DB::enableQueryLog();
    $this->get('/ok')->assertTooManyRequests();
    expect(DB::getQueryLog())->toBeEmpty();
});

it('refills in batches without skipping IPs or counting overlapping blocks twice', function () {
    $rows = [];
    for ($index = 1; $index <= 503; $index++) {
        $rows[] = ['ip_address' => '198.18.'.intdiv($index, num2: 256).'.'.($index % 256)];
    }
    IpBlock::insert([...$rows, $rows[0]]);

    expect(Protec::warmCache())->toBe(503);
    DB::enableQueryLog();
    foreach ($rows as $row) {
        $request = Request::create('/', server: ['REMOTE_ADDR' => $row['ip_address']]);
        expect(Protec::blocked($request))->not->toBeNull();
    }
    expect(DB::getQueryLog())->toBeEmpty();
});

it('skips cache refill for the database driver without querying either table', function (
    string $store,
    string $defaultStore,
) {
    config()->set([
        'protec.cache_store' => $store,
        'cache.default' => $defaultStore,
        'cache.stores.sql-cache' => ['driver' => 'database', 'connection' => 'testing', 'table' => 'unused_cache'],
    ]);
    DB::enableQueryLog();

    expect(Protec::warmCache())->toBe(0);
    $this->artisan('protec:cache')->assertSuccessful();
    expect(DB::getQueryLog())->toBeEmpty();
})->with(['application default' => ['default', 'sql-cache'], 'Protec override' => ['sql-cache', 'array']]);

it('refills using the configured block model and table', function () {
    Schema::rename('protec_ip_blocks', 'custom_ip_blocks');
    config()->set('protec.model', CustomBlock::class);
    $block = CustomBlock::create(['ip_address' => '127.0.0.1', 'context' => ['ticket' => 1]]);

    expect(Protec::warmCache())->toBe(1);
    DB::enableQueryLog();
    $cached = Protec::blocked(Request::create('/', server: ['REMOTE_ADDR' => '127.0.0.1']));
    expect($cached)
        ->toBeInstanceOf(CustomBlock::class)
        ->and($cached->is($block))
        ->toBeTrue()
        ->and($cached->context)
        ->toBe(['ticket' => 1])
        ->and(DB::getQueryLog())
        ->toBeEmpty();
});
