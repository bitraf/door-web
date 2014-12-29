<? header('Content-Type: text/html; charset=UTF-8'); ?>
<?
require_once('secret.php');
$ok = false;

if (array_key_exists('action', $_POST) && $_POST['action'] == 'unlock')
{
  if (array_key_exists('pin', $_POST))
  {
    pg_connect('dbname=p2k12 user=p2k12');

    $res = pg_query_params("SELECT COUNT(*) FROM auth_log WHERE host = $1 AND account IS NULL AND date > NOW() - INTERVAL '6 hour'", array($_SERVER['REMOTE_ADDR']));

    $fail_count = pg_fetch_result($res, 0, 0);

    if ($fail_count < 3)
    {
      $res = @pg_query("SELECT a.account, a.data FROM auth a LEFT JOIN (SELECT account, MAX(date) AS date, COUNT(account) AS logins FROM auth_log al WHERE al.date > current_date - interval '2 weeks' GROUP BY account) al ON al.account = a.account WHERE a.realm = 'door' ORDER BY al.logins DESC NULLS LAST");

      unset ($account);

      while ($row = pg_fetch_assoc($res))
      {
        if (crypt($_POST['pin'], $row['data']) === $row['data'])
        {
          $account = $row['account'];

          break;
        }
      }

      if (isset($account))
      {
        $res = @pg_query_params("SELECT 1 FROM active_members WHERE account = $1 AND (price > 0 OR flag != '')", array($account));

        if (pg_num_rows($res) == 1)
          $ok = true;
        else
          $error = 'Error: Only registered and paying members can use door';
      }

      if ($ok)
      {
        @pg_query_params("INSERT INTO auth_log (host, account, realm) VALUES ($1, $2, 'door')", array($_SERVER['REMOTE_ADDR'], $account));
      }
      else
      {
        @pg_query_params("INSERT INTO auth_log (host, realm) VALUES ($1, 'door')", array($_SERVER['REMOTE_ADDR']));

        $error = 'Incorrect password';
      }
    }
    else
      $error = "Error: Too many login failures";
  }

  if ($ok)
  {
    $error = "Unlocked " . strftime('%H:%M:%S');

    @pg_query_params('INSERT INTO checkins (account) VALUES ($1)', array($account));

    $output = system("/usr/local/bin/bitraf-door-open.sh > /var/www/t 2>&1 &");
    echo "<p>Welcome to Bitraf.</p>";
  }
}
?>
<!DOCTYPE HTML>
<html>
  <head>
    <title>Bitraf Door</title>
    <meta name="viewport" content="width=device-width, initial=scale=1, maximum-scale=1, user-scalable=no">
    <style>
      body { background: #fff; margin: 0; padding: 10px; font-family: sans-serif; text-align: center; }
      p { margin: 0 0 10px; }
      input { margin-bottom: 10px; }
    </style>
  </head>
  <body>
  <? if ($ok): ?>
    <p>Door is open.</p>
  <? else: ?>
    <? if (isset($error)): ?>
      <p><?=$error?></p>
    <? endif ?>
    <form method='post' action='<?=htmlentities($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8')?>'>
      <input type='hidden' name='action' value='unlock'>
      <p>Password:</p>
      <input id='pin' autofocus='autofocus' type='password' name='pin' style='width: 80%; max-width: 300px'><br>
      <input type='submit' value='Unlock'>
    </form>
  <? endif ?>
  </body>
</html>
