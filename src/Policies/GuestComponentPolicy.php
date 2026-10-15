<?php

declare(strict_types=1);

namespace Petecoop\Protec\Policies;

use Illuminate\Http\Request;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;

class GuestComponentPolicy extends RateLimitPolicy
{
    public function evaluate(Detection $detection, Request $request): Limit
    {
        return new Limit(
            attempts: $this->options['attempts'] ?? 20,
            within: $this->options['within'] ?? 600,
            blockFor: $this->options['block_for'] ?? 600,
            rejectWith: $this->options['reject_with'] ?? 401,
        );
    }
}
