<?php

use App\Http\Controllers\Api\ScanController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\WebhookController;

Route::post('/v1/scan', [ScanController::class, 'scan']);

Route::post('/v1/webhooks/threat-intel', [WebhookController::class, 'receiveThreatIntel']);