<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Illuminate\Http\Request;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Protec;
use Symfony\Component\HttpFoundation\Response;

class CustomProtec extends Protec
{
    protected function resolveIp(Request $request): ?string
    {
        return parent::resolveIp($request) === '127.0.0.1' ? '203.0.113.99' : parent::resolveIp($request);
    }

    protected function blockAttributes(string $detector, Detection $detection, int $seconds): array
    {
        return [
            ...parent::blockAttributes($detector, $detection, $seconds),
            'context' => [...$detection->context, 'custom' => true],
        ];
    }

    public function respond(Request $request, ?IpBlock $block = null, int $status = 429): Response
    {
        return parent::respond($request, $block, $status)->setContent('Custom blocked response');
    }
}
