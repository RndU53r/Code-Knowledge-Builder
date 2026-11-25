<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function show(Request $request, $id)
    {
        $rows = DB::select("SELECT * FROM users WHERE id = " . $request->input('id'));
        return response()->json($rows);
    }

    public function import(Request $request)
    {
        $obj = unserialize($request->input('blob'));
        return response()->json($obj);
    }

    public function report(Request $request)
    {
        $out = shell_exec("report " . $request->input('name'));
        $body = file_get_contents($request->input('url'));
        return $out . $body;
    }
}
