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

    public function name(string $detector): string
    {
        return is_a($detector, Detector::class, allow_string: true)
            ? $this->detector($detector)->name()
            : $detector;
    }

    public function escalation(string $detector): ?Escalation
    {
        $options = false;

        foreach ($this->definitions() as $class => $definition) {
            if ($detector !== $class && $detector !== $this->name($class)) {
                continue;
            }

            $options = $definition['escalation'] ?? false;

            break;
        }

        if ($options === false) {
            return null;
        }

        if (! is_array($options)) {
            throw new InvalidArgumentException("Protec escalation for [{$detector}] must be an array or false.");
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
