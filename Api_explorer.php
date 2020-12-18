<?php namespace App\Controllers;

use App\Libraries\SiteGuard;
use Firebase\JWT\JWT;

class Api_explorer extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("api_explorer");
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Home',
								'current_user' => $current_user,
								'userModel' => new \App\Models\User(),
								'groupModel' => new \App\Models\Group()
							);
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('settings/api_explorer', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
		
	}
}
