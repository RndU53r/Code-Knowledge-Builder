<?php
use App\Services\OrderService;

class OrderServiceTest
{
    public function testPlace()
    {
        (new OrderService(null))->place('a');
    }
}
