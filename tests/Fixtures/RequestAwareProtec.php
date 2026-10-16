<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Illuminate\Http\Request;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Protec;

class RequestAwareProtec extends Protec
{
    protected function limitFor(Request $request, Detection $detection, array $policy): Limit
    {
        if ($request->header('X-Test-Immediate') === 'yes' && $request->is('.env')) {
            return new Limit(attempts: 1, blockFor: '2m');
        }

        return parent::limitFor($request, $detection, $policy);
    }
}
