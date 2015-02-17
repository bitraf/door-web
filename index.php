<?php
header('Content-Type: text/html; charset=UTF-8');

// Require that HTTPS be used for the next year, to prevent SSL-stripping MITM 
// attacks on the unencrypted door.bitraf.no redirect domain.
header('Strict-Transport-Security: max-age=31536000');

// Set to a string when the user is identified.  Note that not all users are 
// authorized to unlock the door.
unset($account);

// Set to true when authentication and authorization is complete.
$ok = false;

// Set to true if authentication is disallowed due to rate limiting.
$rate_limited = false;

if (isset($_POST['action'])
    && isset($_POST['pin'])
    && isset($_POST['user'])
    && $_POST['action'] == 'unlock')
{
  require_once('db-connect-string.php');
  pg_connect($db_connect_string);

  // Per-IP failure rate limit.
  $res = pg_query_params("SELECT COUNT(*) FROM auth_log WHERE host = $1 AND account IS NULL AND date > NOW() - INTERVAL '1 hour'", array($_SERVER['REMOTE_ADDR']));
  $fail_count = pg_fetch_result($res, 0, 0);

  if ($fail_count < 10)
  {
    // Retrieve password hash and eligibility to unlock door remotely.
    $res = @pg_query_params(<<<SQL
SELECT account, auth.data,
       (active_members.price > 0 OR active_members.flag != '') AS can_unlock
  FROM auth
  JOIN active_members USING (account)
  JOIN accounts ON accounts.id = account
  WHERE (LOWER(accounts.name) = LOWER($1) OR LOWER(active_members.full_name) = LOWER($1))
    AND auth.realm = 'door'
  ORDER BY can_unlock DESC NULLS LAST
SQL
        , array($_POST['user']));

    $row = pg_fetch_assoc($res);

    if ($row)
    {
      $account = $row['account'];

      if ($row['can_unlock'] != 't')
      {
        $error = 'User not authorized to unlock door';
      }
      else if (crypt($_POST['pin'], $row['data']) !== $row['data'])
      {
        $error = 'Incorrect password';
      }
      else
      {
        $ok = true;
      }
    }
    else
    {
      $error = 'User ' . htmlentities($_POST['user'], ENT_QUOTES, 'utf-8') . ' not found';
    }
  }
  else
  {
    $error = "Too many login failures";
    $rate_limited = true;
  }
  }

if ($ok)
{
  @pg_query_params("INSERT INTO auth_log (host, account, realm) VALUES ($1, $2, 'door')", array($_SERVER['REMOTE_ADDR'], $account));
  @pg_query_params('INSERT INTO checkins (account) VALUES ($1)', array($account));
}
else if ($rate_limited)
{
  @pg_query_params("INSERT INTO auth_log (host, realm) VALUES ($1, 'door')", array($_SERVER['REMOTE_ADDR']));
}
?>
<!DOCTYPE HTML>
<html>
  <head>
    <title>Bitraf Door</title>
    <meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1'>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap-theme.min.css">

    <link href="style/main.css" rel="stylesheet" type="text/css">
	<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
	<script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
  </head>
  <body>
  <div class='container' style='margin-bottom: 20px;'>
    <img src='http://www.bitraf.no/images/bitraf.png' class='image-round'>
  </div>
  <? if ($ok): ?>
    <!-- <p style='font-weight: bold'>Door is open.  Welcome to Bitraf (<?=strftime('%H:%M:%S')?>).</p> -->
	<div class='alert alert-success'>
		<h4>Door is open!</h4>Welcome to Bitraf! 
		<p>(Current time: <?=strftime('%H:%M:%S')?>)</p>
		<!-- TODO: add SQL and PHP for counting <div>You are the 48th member here today.</div> -->
	</div>
  <? else: ?>
    <? if (isset($error)): ?>
	  <div class='alert alert-danger'><h4>Error!</h4><?=$error?></div>
    <? endif ?>
	
  	<div class="panel-group" id="accordion" role="tablist">
	  <div class="panel panel-default">
		<div class="panel-heading" role="tab" id="headingOne">
		  <h4 class="panel-title">
			<a data-toggle="collapse" data-parent="#accordion" href="#collapseOne">
			  <h4><span class='glyphicon glyphicon-question-sign' style='margin-right: 15px;'></span>How do I get access?</h4>
			</a>
		  </h4>
		</div>
		<div id="collapseOne" class="panel-collapse collapse" role="tabpanel">
		  <div class="panel-body">
			You need to enter the Bitraf premises, and log into the console on the P2K12 computer. Type <code>passwd door</code>, and create your personal password.
		  </div>
		</div>
	  </div>
	</div>

	
    <form method=post action='<?=htmlentities($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8')?>'>
      <input type=hidden name=action value=unlock>
	  
	  <h4>Authentication</h4>  
	  <div class='form-group'>	  
	  <div class='input-group input-group-lg'>
		<span class='input-group-addon' id='usernameaddon'><span class='glyphicon glyphicon-user'></span></span>
		<input id="user" name="user" autofocus="autofocus" type="text" class='form-control' placeholder='Username or Fullname'>
	   </div>
	  </div>
	  
	  <div class='form-group'>	  
	  <div class='input-group input-group-lg'>
		<span class='input-group-addon' id='passwordaddon'><span class='glyphicon glyphicon-pencil'></span></span>
        <input id=pin type=password name=pin class='form-control' placeholder='Password'>
	  </div>
	</div>
	
	<div class='container' style='margin-top: 30px; margin-bottom: 200px;'>
    <button type='submit' class='btn btn-lg btn-success' style='padding: 20px 50px 20px 50px;' value='Unlock'>
		<span class='glyphicon glyphicon-lock' style='margin-right: 0px;'></span>
		Unlock
	</button>
	</div>
	
    </form>
  <? endif ?>
   
  </body>
</html>
<?
// We flush the output buffers and perform the unlock operation after the page 
// has rendered to prevent its slowness from stalling the web browser.
flush();

if ($ok)
  system("/usr/local/bin/bitraf-door-open.sh");
