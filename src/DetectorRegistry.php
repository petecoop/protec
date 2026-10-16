<?php

declare(strict_types=1);

namespace Petecoop\Protec;

use InvalidArgumentException;
use Petecoop\Protec\Contracts\Detector;
use Petecoop\Protec\Data\Escalation;

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
        $detector = app()->makeWith($class, ['configuration' => config('protec.detectors.'.$class, [])]);

        if (! $detector instanceof Detector) {
            throw new InvalidArgumentException("Protec detector [{$class}] must implement Detector.");
        }

        return $detector;
    }

    public function escalation(string $class): ?Escalation
    {
        $options = config('protec.detectors.'.$class.'.escalation', default: false);

        if ($options === false) {
            return null;
        }

        if (! is_array($options)) {
            throw new InvalidArgumentException("Protec escalation for [{$class}] must be an array or false.");
        }

        return new Escalation(
            after: $options['after'] ?? 5,
            within: $options['within'] ?? '8h',
            blockFor: array_key_exists('block_for', $options) ? $options['block_for'] : '7d',
        );
    }

    public function historyWindow(): int
    {
        $window = 0;

        foreach ($this->definitions() as $class => $definition) {
            $window = max($window, $this->escalation($class)->within ?? 0);
        }

        return $window;
    }
}
