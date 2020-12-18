<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class Home extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("index");
		$group = $siteGuard->get_group();
		
		if($group->default_index) {
			$params = $_GET; $page_param = htmlspecialchars(http_build_query($params), ENT_QUOTES);
			if($page_param) {
				$str = '?'. $page_param;
			} else {
				$str = '';
			}
			redirect_to(urldecode($group->default_index).$str);
		}
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Home',
								'current_user' => $current_user,
								'userModel' => new \App\Models\User(),
								'groupModel' => new \App\Models\Group(),
								'annModel' => new \App\Models\Announcement()
							);
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('home', $data);
		echo view('pages/footer', $data, ['cache' => 60]);
		
	}
	public function deimpersonate() {
		$siteGuard = new SiteGuard();
		$siteGuard->deimpersonate();
		return redirect()->to(base_url('index'));
	}
}
