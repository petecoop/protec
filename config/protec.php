<?php

declare(strict_types=1);

use Petecoop\Protec\Detectors;
use Petecoop\Protec\Exemptions\AuthenticatedRequests;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Patterns;

return [
    // Disable detection and enforcement without removing the package.
    'enabled' => env('PROTEC_ENABLED', default: true),

    // Eloquent model for individual IP blocks and their history. Custom models
    // should extend IpBlock.
    'model' => IpBlock::class,

    // Groups that receive protection before route actions run. Global response
    // inspection also catches unrouted 404s. Additional groups can be added here.
    'middleware_groups' => ['web', 'api'],

    /*
     | Detectors identify activity; their policy sets when and how long to block.
     | Set a detector to false (or enabled => false) to disable it. Custom detector
     | classes are resolved through Laravel's container.
     |
     | attempts: matching requests needed; within: counting window;
     | block_for: block duration, or null for a permanent block;
     | reject_with: optional HTTP error returned before the block threshold.
     | Durations accept integer seconds or Carbon intervals such as '10m', '8h',
     | '7d', or '1h 30m'. Set attempts to 1 to block on the first match.
     |
     | Escalation allows further blocking if the ip repeatedly triggers blocks for this detector within a rolling window.
     | Use false to disable it, or ['after' => 5, 'within' => '8h', 'block_for' => '7d'].
     | Retained automatic blocks count even when escalation was disabled before.
     | Active-block requests and manual blocks do not add offences.
     */
    'detectors' => [
        Detectors\ScannerProbe::class => [
            'policy' => ['attempts' => 10, 'within' => '1m', 'block_for' => '1h'],
            'escalation' => false,

            // Scanner URL patterns, add your own strings or arrays or remove existing rules.
            // Only matching 404 responses are counted.
            'patterns' => [
                Patterns::WORDPRESS,
                Patterns::CONFIGURATION,
                Patterns::VERSION_CONTROL,
                Patterns::DATABASE,
                Patterns::PHP,
                Patterns::LARAVEL,
                Patterns::TELESCOPE,
                Patterns::SERVERS,
                Patterns::OTHER_PLATFORMS,
            ],

            // Scanner URL exclusions
            'except' => [],
        ],
        Detectors\CorruptLivewirePayload::class => [
            'policy' => ['attempts' => 5, 'within' => '10m', 'block_for' => '10m'],
            'escalation' => false,

            // Keep matched exceptions in Laravel's normal error reporting when true.
            'report' => false,
        ],
        // Opt in after listing the components that guests should be able to use.
        Detectors\GuestLivewireComponents::class => [
            'enabled' => false,
            'policy' => ['attempts' => 20, 'within' => '10m', 'block_for' => '10m', 'reject_with' => 401],
            'escalation' => false,

            // Component names, classes, or preset arrays allowed for guests.
            // Empty denies all. Opt in to the Filament preset when needed.
            'components' => [
                // \Petecoop\Protec\GuestComponents::FILAMENT,
            ],
        ],
    ],

    // Matching exemptions skip detection AND enforcement of existing blocks.
    // Remove AuthenticatedRequests to apply protection to signed-in users too.
    'exemptions' => [AuthenticatedRequests::class],

    // Retain rows after expiry or manual unblocking for model:prune. Accepts an
    // interval or integer seconds; 0 prunes immediately, while keeping any enabled
    // escalation history window. Active blocks are never pruned.
    'retention' => '30d',
];
