<?php
// Set cookie if ?set=... is present
if (isset($_GET['set'])) {
    setcookie('animal', $_GET['set'], time() + 60*60*24*30, '/');
    header('Location: cookie.php');
    exit;
}

// Delete cookie if ?delete=1 is present
if (isset($_GET['delete'])) {
    setcookie('animal', '', time() - 3600, '/');
    header('Location: cookie.php');
    exit;
}

$current = $_COOKIE['animal'] ?? '(not set)';
?>
<!doctype html>
<html>
  <body>
    <p>Current cookie animal: <b><?= htmlspecialchars($current) ?></b></p>

    <form method="get">
      <input name="set" placeholder="value for animal">
      <button type="submit">Set cookie</button>
    </form>

    <form method="get">
      <input type="hidden" name="delete" value="1">
      <button type="submit">Delete cookie</button>
    </form>
  </body>
</html>
