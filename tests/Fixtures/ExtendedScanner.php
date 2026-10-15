<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Petecoop\Protec\Detectors\ScannerProbe;

class ExtendedScanner extends ScannerProbe
{
    public function patterns(): array
    {
        return [...parent::patterns(), 'private-admin/*'];
    }
}
