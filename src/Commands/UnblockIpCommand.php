<?php

declare(strict_types=1);

namespace Petecoop\Protec\Commands;

use Illuminate\Console\Command;
use Petecoop\Protec\Protec;

class UnblockIpCommand extends Command
{
    protected $signature = 'protec:unblock {ip : The IPv4 or IPv6 address to unblock}';

    protected $description = 'Lift all active Protec blocks for an IP address';

    public function handle(Protec $protec): int
    {
        $ip = (string) $this->argument('ip');

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $this->error('A valid IPv4 or IPv6 address is required.');

            return self::FAILURE;
        }

        if (! $protec->unblock($ip)) {
            $this->info('No active block found.');

            return self::SUCCESS;
        }

        $this->info('IP address unblocked.');

        return self::SUCCESS;
    }
}
