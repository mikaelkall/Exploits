<?php
    // This is a LFI vuln
    $file = $_GET['file'];
    if(isset($file))
    {
        include("$file");
    }
    else
    {
        include("home.php");
    }
?>
