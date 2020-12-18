<?php namespace App\Controllers;

use App\Libraries\SiteGuard;

class Usage_reports extends BaseController {
	public function index() {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("usage_reports");
		
		$data = array(  'siteGuard' => $siteGuard,
								'title' => 'Manage Users',
								'current_user' => $current_user,
								'userModel' => new \App\Models\User(),
								'groupModel' => new \App\Models\Group(),
								'logModel' => new \App\Models\SiteGuardLog()
							);
		
		echo view('pages/header', $data, ['cache' => 60]);
		echo view('pages/navbar', $data, ['cache' => 60]);
		echo view('reports/usage_reports', $data);
		echo view('pages/footer', $data, ['cache' => 60]);	
	}
	
	public function clear($hash) {
		$siteGuard = new SiteGuard();
		$current_user = $siteGuard->get_user();
		$siteGuard->page_access("usage_reports");
		
		$logModel = new \App\Models\SiteGuardLog();
		$userModel = new \App\Models\User();
		
		if($hash != $siteGuard->csrf) {
			$msg = siteGuard_msg('timestamp-fail');
			return redirect()->to(base_url("usage_reports?edit=fail&msg={$msg}"));
			exit();
		}
		if(!$siteGuard->privilege("usage_reports.delete")) {
			$msg = siteGuard_msg('restricted_privilege');
			return redirect()->to(base_url("usage_reports?edit=fail&msg={$msg}"));
		}
		
		$success = 0;
		$fail = 0;
		
		$query=" id != 0 ";
		if(isset($_GET['action']) && !empty($_GET['action']) ) {
			$query .= " AND action LIKE '%". escape_value($_GET['action']) .  "%' ";
		}
		
		if(isset($_GET['term']) && !empty($_GET['term']) ) {
			$query .= " AND msg LIKE '%". escape_value($_GET['term']) .  "%' ";
		}
		
		if(isset($_GET['user_id']) && !empty($_GET['user_id']) ) {
			$query .= " AND  user_id = '" . escape_value($_GET['user_id']) . "' ";
		}

		if(isset($_GET['from_date']) && !empty($_GET['from_date']) && isset($_GET['to_date']) && !empty($_GET['to_date']) ) {
			$from = escape_value($_GET['from_date']);
			$to = escape_value($_GET['to_date']);
			$query .= " AND  DATE(done_at) >= DATE('{$from}') AND DATE(done_at) <= DATE('{$to}') ";
		}
		$all_logs = $logModel->get_everything($query);
		if($all_logs) {
			foreach ($all_logs as $log) {
				if($logModel->delete($log->id)) {
					$success = 1;
				} else {
					$fail = 1;
				}
			}
			if($success == "1") {
				$logModel->log_action($current_user->id , "Clear Usage Log" , 'Clear application usage logs');
				$msg = siteGuard_msg('delete-success');
				return redirect()->to(base_url("usage_reports?edit=success&msg={$msg}"));
			} else {
				$msg = siteGuard_msg('delete-fail');
				return redirect()->to(base_url("usage_reports?edit=fail&msg={$msg}"));
			}
		} else {
			return redirect()->to(base_url("usage_reports"));
		}
	}
}
