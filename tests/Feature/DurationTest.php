<?php

declare(strict_types=1);

use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Duration;

it('converts durations to whole seconds', function (int|string $value, int $expected) {
    expect(Duration::seconds($value))->toBe($expected);
})->with([
    [0,                    0],
    [60,                   60],
    ['30s',                30],
    ['10m',                600],
    ['8h',                 28_800],
    ['7d',                 604_800],
    ['2w',                 1_209_600],
    ['1h 30m',             5400],
    ['1h30m',              5400],
    [' 8H ',               28_800],
    ['2 hours 15 minutes', 8100],
    ['1.5h',               5400],
]);

it('rejects invalid, negative, fractional-second and overflowing durations', function (int|string $value) {
    expect(fn () => Duration::seconds($value))->toThrow(InvalidArgumentException::class);
})->with([
    -1,
    '',
    '60',
    'tomorrow',
    'junk 8h',
    '1h junk',
    '-2h',
    '1h -30m',
    '0.5s',
    '3cats',
    '99999999999999999999999999999999999d',
]);

it('requires positive limit durations while allowing null for permanent bans', function () {
    expect(fn () => new Limit(within: '0s'))->toThrow(InvalidArgumentException::class);
    expect(fn () => new Limit(blockFor: 0))->toThrow(InvalidArgumentException::class);
    $limit = new Limit(within: '1m', blockFor: null);
    expect($limit->within)->toBe(60)->and($limit->blockFor)->toBeNull();
});

it('applies shorthand detector durations during HTTP requests', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.Petecoop\Protec\Detectors\ScannerProbe::class.'.policy', [
        'attempts' => 2,
        'within' => '1m',
        'block_for' => '2h',
    ]);
    $this->get('/.env')->assertNotFound();
    $this->get('/.env')->assertTooManyRequests();
    expect(Petecoop\Protec\Models\IpBlock::query()->sole()->expires_at->equalTo(now()->addHours(2)))->toBeTrue();
});

it('accepts retention durations and treats integers as seconds', function () {
    $this->freezeSecond();
    config()->set('protec.retention', 60);
    Petecoop\Protec\Facades\Protec::ban('203.0.113.1', for: 1);
    $this->travel(60)->seconds();
    $this->artisan('model:prune', ['--model' => [Petecoop\Protec\Models\IpBlock::class]])->assertSuccessful();
    $this->assertDatabaseCount('protec_ip_blocks', 1);
    $this->travel(1)->seconds();
    $this->artisan('model:prune', ['--model' => [Petecoop\Protec\Models\IpBlock::class]])->assertSuccessful();
    $this->assertDatabaseCount('protec_ip_blocks', 0);
});
