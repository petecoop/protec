<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Petecoop\Protec\Detectors\ScannerProbe;

class NamedScanner extends ScannerProbe
{
    public function name(): string
    {
        return 'custom-scanner';
    }
}
