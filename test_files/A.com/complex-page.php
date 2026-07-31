<?php
if (!isset($_COOKIE['animal'])) {
    setcookie('animal', 'pigs', time() + 30*24*3600, '/');
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}
$animal = $_COOKIE['animal'] ?? 'cows';
?>
<!doctype html>
<head><title>Alice's Page 3</title></head>
<html>
  <body>
          <p>My name is Alice.</p>
          <p>I like sheep and <?php echo htmlspecialchars($animal); ?>.</p>
          <p hidden>I also especially like donkeys.</p>
<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
          <p>Finally, I like fish.</p>
  </body>
</html>
