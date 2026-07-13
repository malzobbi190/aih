<?php

//To Handle Session Variables on This Page
session_start();

//Including Database Connection From db.php file to avoid rewriting in all files
require_once("db.php");

//If user Actually clicked login button 
if(isset($_POST)) {
	// Validate CSRF token

    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF validation failed");
    }


	//Escape Special Characters in String
	$email = mysqli_real_escape_string($conn, $_POST['email']);
	
	$password = mysqli_real_escape_string($conn, $_POST['password']);

	// Use this when creating a password
  	//$encryptedPassword = password_hash($password, PASSWORD_DEFAULT);

	//sql query to check company login
	$stmt = $conn->prepare("SELECT id_company, companyname, email,password, active FROM company WHERE email=? LIMIT 1");

	$stmt->bind_param("s", $email);
	$stmt->execute();
	$result = $stmt->get_result();
	
	

	//if company table has this this login details
if ($row = $result->fetch_assoc()) {		//output data

			if($row['active'] == '2') {
				$_SESSION['companyLoginError'] = "Your Account Is Still Pending Approval.";
				header("Location: login-company.php");
				exit();
			} else if($row['active'] == '0') {
				$_SESSION['companyLoginError'] = "Your Account Is Rejected. Please Contact For More Info.";
				header("Location: login-company.php");
				exit();
			} else if($row['active'] == '1') {
					

				// active 1 means admin has approved account.
				//Set some session variables for easy reference
				 if (password_verify($password, $row['password'])) {
					
							// Regenerate session to prevent fixation
							session_regenerate_id(true);
							$_SESSION['name'] = $row['companyname'];
							$_SESSION['id_company'] = $row['id_company'];

							// CSRF token should be single-use
							unset($_SESSION['csrf_token']);

							header("Location: company/index.php");
							exit();
				}else{
						$_SESSION['companyLoginError'] = true;
 						header("Location: login-company.php");
		exit();

				}
				
			} else if($row['active'] == '3') {
				$_SESSION['companyLoginError'] = "Your Account Is Deactivated. Contact Admin For Reactivation.";
				header("Location: login-company.php");
				exit();
			}
		
 	} else {
 		//if no matching record found in user table then redirect them back to login page
 		$_SESSION['companyLoginError'] = true;
 		header("Location: login-company.php");
		exit();
 	}

 	//Close database connection. Not compulsory but good practice.
 	$conn->close();

} else {
	//redirect them back to login page if they didn't click login button
	
	header("Location: login-company.php");
	exit();
}