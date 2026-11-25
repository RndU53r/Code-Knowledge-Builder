<?php
namespace App\Http\Controllers;

use App\Services\OrderService;
use Illuminate\Http\Request;

class OrderController
{
    public function __construct(private OrderService $service)
    {
    }

    public function create(Request $request)
    {
        return $this->service->place($request->input('item'));
    }
}
