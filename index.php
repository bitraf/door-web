<?
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
  pg_connect('dbname=p2k12 user=p2k12');

  // Per-IP rate failure limit.
  $res = pg_query_params("SELECT COUNT(*) FROM auth_log WHERE host = $1 AND account IS NULL AND date > NOW() - INTERVAL '6 hour'", array($_SERVER['REMOTE_ADDR']));
  $fail_count = pg_fetch_result($res, 0, 0);

  if ($fail_count < 3)
  {
    // Retrieve password hash and eligivility to unlock door remotely.
    $res = @pg_query_params(<<<SQL
SELECT auth.data,
       (active_members.price > 0 OR active_members.flag != '') AS can_unlock
  FROM auth
  JOIN active_members USING (account)
  JOIN accounts ON accounts.id = account
  WHERE accounts.name = $1
    AND auth.realm = 'door'
SQL
        , array($_POST['user']));

    $row = pg_fetch_assoc($res);

    if ($row)
    {
      $account = trim($_POST['user']);

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
    $error = "Error: Too many login failures";
    $rate_limited = true;
  }
}

if ($ok)
{
  @pg_query_params("INSERT INTO auth_log (host, account, realm) VALUES ($1, $2, 'door')", array($_SERVER['REMOTE_ADDR'], $account));
  @pg_query_params('INSERT INTO checkins (account) VALUES ($1)', array($account));

  system("/usr/local/bin/bitraf-door-open.sh &");
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
    <meta name='viewport' content='width=device-width, initial=scale=1, maximum-scale=1'>
    <style>
      body { background: #fff; margin: 0; padding: 10px; font-family: sans-serif; text-align: center; }
      p { margin: 0 0 10px; }
      input { margin-bottom: 10px; }
    </style>
  </head>
  <body>
  <? if ($ok): ?>
    <p style='font-weight: bold'>Door is open.  Welcome to Bitraf (<?=strftime('%H:%M:%S')?>).</p>
  <? else: ?>
    <? if (isset($error)): ?>
      <p><?=$error?></p>
    <? endif ?>
    <form method=post action='<?=htmlentities($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8')?>'>
      <input type=hidden name=action value=unlock>
      <p>Username:</p>
      <input id=user autofocus=autofocus type=text name=user style='width: 80%; max-width: 300px'><br>
      <p>Password:</p>
      <input id=pin type=password name=pin style='width: 80%; max-width: 300px'><br>
      <input type=submit value=Unlock>
    </form>
  <? endif ?>
  </body>
</html>
