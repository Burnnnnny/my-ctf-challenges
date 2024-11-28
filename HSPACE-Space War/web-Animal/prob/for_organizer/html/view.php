<?php
if (isset($_GET['animal'])) {
        $animal = $_GET['animal'];
        $mime_type = mime_content_type($animal);
        header("Content-Type: $mime_type");
        echo file_get_contents($animal);
        exit;
}
 else {
    echo "<script>alert('Animal name is empty.')</script><meta http-equiv=\"refresh\" content=\"0;url=/index.php\" />";
    exit;
}
?>
