<?php
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::get('/users/{id}', [UserController::class, 'show']);
Route::post('/users/import', 'UserController@import')->middleware('auth');

Route::prefix('api')->group(function () {
    Route::get('/report', [UserController::class, 'report']);
    Route::post('/upload', function () {
        $name = $_POST['name'];
        echo $name;
    });
});
