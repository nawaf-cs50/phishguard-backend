<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scanned_urls', function (Blueprint $table) {
            $table->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            $table->text('url');
            $table->char('url_hash', 64)->unique();
            $table->enum('status', ['safe', 'suspicious', 'malicious', 'pending'])->default('pending');
            $table->jsonb('vt_result')->nullable();
            $table->jsonb('gsb_result')->nullable();
            $table->timestampTz('scanned_at')->useCurrent();
            $table->timestampTz('expires_at');
            $table->timestampsTz();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scanned_urls');
    }
};