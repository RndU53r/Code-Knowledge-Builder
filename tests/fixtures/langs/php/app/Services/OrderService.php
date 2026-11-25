<?php
namespace App\Services;

use App\Repos\OrderRepo;

class OrderService
{
    public function __construct(private OrderRepo $repo)
    {
    }

    public function place($item)
    {
        return $this->repo->save($item);
    }
}
