<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('ip_blocks', static function (Blueprint $table): void {
            $table->id();
            $table->ipAddress('ip_address');
            $table->string('detector')->nullable();
            $table->string('reason')->nullable();
            $table->json('context')->nullable();
            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamp('unblocked_at')->nullable()->index();
            $table->timestamps();

            $table->index(['ip_address', 'unblocked_at', 'expires_at']);
            $table->index(['ip_address', 'detector', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ip_blocks');
    }
};
