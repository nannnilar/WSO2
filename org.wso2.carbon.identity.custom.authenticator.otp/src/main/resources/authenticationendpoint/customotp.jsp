<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OTP Verification</title>
    <link rel="stylesheet" href="https://localhost:9444/authenticationendpoint/css/bootstrap.min.css"/>
    <link rel="stylesheet" href="https://localhost:9444/authenticationendpoint/css/authenticationendpoint.css"/>
    <style>
        body.login-page {
            background-color: #f2f2f2;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        }
        .otp-box {
            max-width: 420px;
            margin: 80px auto;
            padding: 35px;
            border-radius: 8px;
            background-color: #fff;
            box-shadow: 0 0 25px rgba(0,0,0,0.1);
        }
        .otp-box h2 {
            color: #f58220;
            text-align: center;
            margin-bottom: 20px;
            font-weight: 600;
        }
        .otp-box input[type=text] {
            width: 100%;
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 4px;
            border: 1px solid #ccc;
            font-size: 14px;
        }
        .otp-box input[type=submit] {
            width: 100%;
            padding: 12px;
            background-color: #f58220;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            font-size: 15px;
            transition: background 0.3s;
        }
        .otp-box input[type=submit]:hover {
            background-color: #e06b00;
        }
        .info-text {
            text-align: center;
            color: #333;
            font-size: 14px;
            margin-bottom: 15px;
        }
        .success-text {
            color: green;
            text-align: center;
            margin-bottom: 15px;
        }
        .error-text {
            color: red;
            text-align: center;
            margin-bottom: 15px;
        }
        label {
            font-weight: 500;
            margin-bottom: 5px;
            display: block;
        }
    </style>
</head>
<body class="login-page">
<div class="otp-box">
    <h2>OTP Verification</h2>
    <div class="info-text">
        Enter the OTP sent to your registered email/phone.
    </div>

    <c:if test="${not empty errorMsg}">
        <div class="error-text">${errorMsg}</div>
    </c:if>

    <c:if test="${not empty successMsg}">
        <div class="success-text">${successMsg}</div>
    </c:if>

    <form method="post" action="../commonauth">
        <input type="hidden" name="sessionDataKey" value="${param.sessionDataKey}" />
        <input type="hidden" name="authenticator" value="${param.authenticator}" />
        <input type="hidden" name="identifier" value="${param.identifier}" />
        <input type="hidden" name="spId" value="${param.spId}" />
        <input type="hidden" name="otp-submitted" value="true" />

        <label for="otp-code">OTP Code</label>
        <input type="text" name="otp-code" id="otp-code" placeholder="Enter OTP" required />

        <input type="submit" value="Verify OTP" />
    </form>
</div>


</body>
</html>
