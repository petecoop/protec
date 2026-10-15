<?php

declare(strict_types=1);

namespace Petecoop\Protec;

use InvalidArgumentException;
use Petecoop\Protec\Contracts\Detector;
use Petecoop\Protec\Contracts\Policy;
use Petecoop\Protec\Policies\RateLimitPolicy;

class DetectorRegistry
{
    /** @return iterable<class-string<Detector>, array<string, mixed>> */
    public function definitions(): iterable
    {
        foreach (config('protec.detectors', []) as $class => $definition) {
            if ($definition === false) {
                continue;
            }

            if (! is_array($definition)) {
                throw new InvalidArgumentException(
                    "Protec detector [{$class}] must be configured with an array or false.",
                );
            }

            if ($definition['enabled'] ?? true) {
                yield $class => $definition;
            }
        }
    }

    /** @param class-string<Detector> $class */
    public function detector(string $class): Detector
    {
        $detector = app($class);

        if (! $detector instanceof Detector) {
            throw new InvalidArgumentException("Protec detector [{$class}] must implement Detector.");
        }

        return $detector;
    }

    /** @param array<string, mixed> $definition */
    public function policy(array $definition): Policy
    {
        $policy = app()->makeWith($definition['policy'] ?? RateLimitPolicy::class, [
            'options' => $definition['options'] ?? [],
        ]);

        if (! $policy instanceof Policy) {
            throw new InvalidArgumentException('Protec policies must implement Policy.');
        }

        return $policy;
    }
}
