<?php
session_start();

// Database credentials
$db_host = 'localhost';
$db_username = 'root';
$db_password = '';
$db_name = 'chatbox';

// Establish a database connection
$conn = new mysqli($db_host, $db_username, $db_password, $db_name);

// Check connection
if ($conn->connect_error) {
    echo "Connection failed: " . $conn->connect_error;
    error_log("Database connection failed: " . $conn->connect_error);
    exit;
} else {
    echo "Connected successfully!";
}

// Get the username and password from the login form
$username = $_POST['username'];
$password = $_POST['password'];

error_log("Username: $username"); // Add this line here
error_log("Password: $password"); // Add this line here

// Prepare a statement to retrieve the salt and password
$stmt = $conn->prepare("SELECT salt, password FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
echo $stmt->error; // Add this line here
$result = $stmt->get_result();
$row = $result->fetch_assoc();

if ($row) {
    $salt = $row['salt'];
    $stored_password = $row['password'];
    echo "Stored password: $stored_password\n"; // Add this line here
    echo "Salt: $salt\n"; // Add this line here

    $hashedPW = hash('sha256', $password . $salt);
    echo "Hashed password: $hashedPW\n"; // Add this line here

    // Check if the hashed password matches the stored password
    if ($hashedPW === $stored_password) {
        echo "Passwords match!\n"; // Add this line here
        // Login successful, regenerate the session ID
        session_regenerate_id();
        $_SESSION['username'] = $username;
        header("location: index.php");
        exit;
    } else {
        echo "Passwords do not match!\n"; // Add this line here
        echo "<script>alert('Wrong Username or Password, Retry.'); window.location.replace('loginform.php'); </script>";
        exit;
    }
} else {
    echo "<script>alert('User not found, Retry.'); window.location.replace('loginform.php'); </script>";
    exit;
}