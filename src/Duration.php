<?php

declare(strict_types=1);

namespace Petecoop\Protec;

use Carbon\CarbonInterval;
use Carbon\Exceptions\InvalidIntervalException;
use InvalidArgumentException;

class Duration
{
    public static function seconds(int|string $duration): int
    {
        if (is_int($duration)) {
            if ($duration < 0) {
                throw new InvalidArgumentException('Protec durations cannot be negative.');
            }

            return $duration;
        }

        $duration = trim($duration);

        // Carbon's fromString() can otherwise skip text before the first number.
        if (preg_match('/\A(?:\d+(?:\.\d+)?\h*[a-z]+\h*)+\z/i', $duration) !== 1) {
            throw new InvalidArgumentException(
                "Invalid Protec duration [{$duration}]. Use seconds or an interval such as 8h.",
            );
        }

        preg_match_all('/\d+(?:\.\d+)?/', $duration, $numbers);
        foreach ($numbers[0] as $number) {
            if ((float) $number >= PHP_INT_MAX) {
                throw new InvalidArgumentException('Protec duration exceeds the integer range.');
            }
        }

        try {
            $seconds = CarbonInterval::fromString($duration)->totalSeconds;
        } catch (InvalidIntervalException $exception) {
            throw new InvalidArgumentException("Invalid Protec duration [{$duration}].", previous: $exception);
        }

        if (! is_finite($seconds) || $seconds >= PHP_INT_MAX || floor($seconds) !== $seconds) {
            throw new InvalidArgumentException(
                'Protec durations must resolve to a whole number of seconds within the integer range.',
            );
        }

        return (int) $seconds;
    }
}
