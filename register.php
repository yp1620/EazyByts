<?php
	$servername = "localhost";
	$username = "root";
	$password = "";
	$dbname = "chatbox";

	$conn = new mysqli($servername, $username, $password, $dbname);

	if ($conn->connect_error) {
		die("Connection failed: " . $conn->connect_error);
	}

	if(isset($_SESSION['username'])){
 		 echo "<script>alert('Password Mismatch Session '); window.location.replace('chatterbox/index.php');</script>";
 	}

	if(isset($_POST['done'])){


		$uname = filter_var($_POST['user'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$pass = filter_var($_POST['pass'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$pass2 = filter_var($_POST['confirm_p'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$salt = bin2hex(random_bytes(32));
		$saltedPW =  $pass . $salt;
		$hashedPW = hash('sha256',$saltedPW);

		if($pass != $pass2){
			echo "<script>alert('Password Mismatch incorrect'); window.location.replace('register.php');</script>";

		}else{
			$stmt = $conn->prepare("SELECT username FROM users WHERE username=?");
			$stmt->bind_param("s", $uname);
			$stmt->execute();
			$stmt->store_result();
			if($stmt->num_rows > 0){
				echo "<script>alert('User Already Exists'); window.location.replace('loginform.php');</script>";
			}else{
				$stmt = $conn->prepare("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)");
				$stmt->bind_param("sss", $uname, $hashedPW, $salt);
				$stmt->execute();
				echo $stmt->error;
				echo "<script>alert('SIGN UP SUCCESSFUL')</script>";
				echo "<script>window.location.replace('loginform.php');</script>";
			}
		}
	}

	$conn->close();