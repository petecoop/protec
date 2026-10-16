<?php

declare(strict_types=1);

use Petecoop\Protec\Detectors;
use Petecoop\Protec\Exemptions\AuthenticatedRequests;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Patterns;

return [
    // Disable detection and enforcement without removing the package.
    'enabled' => env('PROTEC_ENABLED', default: true),

    // Eloquent model for current IP blocks. Custom models should extend IpBlock.
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
     | block_for: block duration, or null for a permanent ban;
     | reject_with: optional HTTP error returned before the block threshold.
     | Durations accept integer seconds or Carbon intervals such as '10m', '8h',
     | '7d', or '1h 30m'. Set attempts to 1 to block on the first match.
     |
     | Escalation allows further blocking if the ip repeatedly triggers blocks for this detector within a rolling window.
     | Use false to disable it, or ['after' => 5, 'within' => '8h', 'block_for' => '7d'].
     | Active-block requests and manual bans do not add offences.
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
        ],
        // Opt in after listing the components that guests should be able to use.
        Detectors\DisallowedLivewireComponent::class => [
            'enabled' => false,
            'policy' => ['attempts' => 20, 'within' => '10m', 'block_for' => '10m', 'reject_with' => 401],
            'escalation' => false,
        ],
    ],

    // Matching exemptions skip detection AND enforcement of existing blocks.
    // Remove AuthenticatedRequests to apply protection to signed-in users too.
    'exemptions' => [AuthenticatedRequests::class],

    'livewire' => [
        // Component names or classes allowed for guests when the opt-in
        // DisallowedLivewireComponent detector is enabled. Empty denies all.
        'guest_components' => [],

        // Allowed guest components that reject property updates. Action calls
        // are still permitted and must authorize their own sensitive behaviour.
        'read_only_components' => [],
    ],

    // Keep known Livewire tampering in application error reporting when true.
    'report_livewire_tampering' => false,

    // Retain expired rows for model:prune. Accepts an interval or integer seconds;
    // 0 prunes immediately, while keeping any enabled escalation history window.
    // Permanent bans are never pruned.
    'retention' => '30d',
];
