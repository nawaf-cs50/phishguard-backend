<?php

use App\Http\Controllers\Api\ScanController;
use Illuminate\Support\Facades\Route;

Route::post('/v1/scan', [ScanController::class, 'scan']);