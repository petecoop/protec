<?php

declare(strict_types=1);

namespace Petecoop\Protec\Policies;

use Illuminate\Http\Request;
use Petecoop\Protec\Contracts\Policy;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;

class RateLimitPolicy implements Policy
{
    /** @param array{attempts?: int, within?: int, block_for?: int, reject_with?: int} $options */
    public function __construct(
        protected array $options = [],
    ) {}

    public function evaluate(Detection $detection, Request $request): Limit
    {
        return new Limit(
            attempts: $this->options['attempts'] ?? 5,
            within: $this->options['within'] ?? 600,
            blockFor: $this->options['block_for'] ?? 600,
            rejectWith: $this->options['reject_with'] ?? null,
        );
    }
}
