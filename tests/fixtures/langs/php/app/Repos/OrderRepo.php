<?php
namespace App\Repos;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

class BaseRepo
{
    public function save($item)
    {
        return $item;
    }
}

class OrderRepo extends BaseRepo
{
    public function save($item)
    {
        Http::get('http://billing/charge');
        DB::select("SELECT * FROM orders WHERE id = " . $item);
        return parent::save($item);
    }
}
