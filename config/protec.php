<?php

declare(strict_types=1);

use Petecoop\Protec\Detectors;
use Petecoop\Protec\Exemptions\AuthenticatedRequests;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Policies\GuestComponentPolicy;
use Petecoop\Protec\Policies\RateLimitPolicy;

return [
    'enabled' => true,

    'model' => IpBlock::class,

    'detectors' => [
        Detectors\ScannerProbe::class => [
            'policy' => RateLimitPolicy::class,
            'options' => ['attempts' => 10, 'within' => 60, 'block_for' => 3600],
        ],
        Detectors\CorruptLivewirePayload::class => [
            'policy' => RateLimitPolicy::class,
            'options' => ['attempts' => 5, 'within' => 600, 'block_for' => 600],
        ],
        Detectors\DisallowedLivewireComponent::class => [
            'enabled' => false,
            'policy' => GuestComponentPolicy::class,
            'options' => ['attempts' => 20, 'within' => 600, 'block_for' => 600],
        ],
    ],

    'exemptions' => [AuthenticatedRequests::class],

    'livewire' => [
        'guest_components' => [],
        'read_only_components' => [],
    ],

    'report_livewire_tampering' => false,

    // Used by the model's standard Laravel model:prune support.
    'retention_days' => 30,
];
