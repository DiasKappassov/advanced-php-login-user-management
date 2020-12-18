<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class Active_sessions extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("active_sessions");
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Manage Users',
								'current_user' => $current_user,
								'userModel' => new \App\Models\User(),
								'groupModel' => new \App\Models\Group(),
								'onlineModel' => new \App\Models\Online()
							);
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('reports/active_sessions', $data);
		echo view('pages/footer', $data, ['cache' => 60]);	
	}
	
	public function revoke($session_id, $hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("active_sessions");
		
		$onlineModel = new \App\Models\Online();
		$userModel = new \App\Models\User();
		
		if(!$siteGuard->privilege("active_sessions.revoke")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("active_sessions?edit=fail&msg={$msg}"));
		}
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("active_sessions?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$onlineModel->exists('id',$session_id)) {
			return redirect()->to(base_url("active_sessions"));
			exit();
		}
		$this_obj = $onlineModel->get_specific_id($session_id);
		if($onlineModel->delete($session_id)) {
			session_id($this_obj->session);
			session_destroy();
			$msg = siteGuard_msg('revoke-success');
			$user = $userModel->get_specific_id($this_obj->user_id);
			$log = new \App\Models\SiteGuardLog();
			$log->log_action($current_user->id , "Revoke Session" , "Revoke Session of user ({$user->name}) - id #({$user->id})");
			return redirect()->to(base_url("active_sessions?edit=success&msg={$msg}"));
		} else {
			$msg = siteGuard_msg('delete-fail');
			return redirect()->to(base_url("active_sessions?edit=fail&msg={$msg}"));
		}
	}
}
